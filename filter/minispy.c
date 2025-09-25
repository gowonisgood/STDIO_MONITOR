/*++

Copyright (c) 1989-2002  Microsoft Corporation

Module Name:

    MiniSpy.c

Abstract:

    This is the main module for the MiniSpy mini-filter.

Environment:

    Kernel mode

--*/

#include "mspyKern.h"
#include <stdio.h>

//
//  Global variables
//

MINISPY_DATA MiniSpyData;
NTSTATUS StatusToBreakOn = 0;

//---------------------------------------------------------------------------
//  Function prototypes
//---------------------------------------------------------------------------
DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );


NTSTATUS
SpyMessage (
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

NTSTATUS
SpyConnect(
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
    );

VOID
SpyDisconnect(
    _In_opt_ PVOID ConnectionCookie
    );

NTSTATUS
SpyEnlistInTransaction (
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

//---------------------------------------------------------------------------
//  Assign text sections for each routine.
//---------------------------------------------------------------------------

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(PAGE, SpyFilterUnload)
    #pragma alloc_text(PAGE, SpyQueryTeardown)
    #pragma alloc_text(PAGE, SpyConnect)
    #pragma alloc_text(PAGE, SpyDisconnect)
    #pragma alloc_text(PAGE, SpyMessage)
#endif


#define SetFlagInterlocked(_ptrFlags,_flagToSet) \
    ((VOID)InterlockedOr(((volatile LONG *)(_ptrFlags)),_flagToSet))
    
//---------------------------------------------------------------------------
//                      ROUTINES
//---------------------------------------------------------------------------

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This routine is called when a driver first loads.  Its purpose is to
    initialize global state and then register with FltMgr to start filtering.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.
    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Status of the operation.

--*/
{
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    NTSTATUS status = STATUS_SUCCESS;

    try {

        //
        // Initialize global data structures.
        //

        MiniSpyData.LogSequenceNumber = 0;
        MiniSpyData.MaxRecordsToAllocate = DEFAULT_MAX_RECORDS_TO_ALLOCATE;
        MiniSpyData.RecordsAllocated = 0;
        MiniSpyData.NameQueryMethod = DEFAULT_NAME_QUERY_METHOD;

        MiniSpyData.DriverObject = DriverObject;

        InitializeListHead( &MiniSpyData.OutputBufferList );
        KeInitializeSpinLock( &MiniSpyData.OutputBufferLock );

        ExInitializeNPagedLookasideList( &MiniSpyData.FreeBufferList,
                                         NULL,
                                         NULL,
                                         POOL_NX_ALLOCATION,
                                         RECORD_SIZE,
                                         SPY_TAG,
                                         0 );

#if MINISPY_VISTA

        //
        //  Dynamically import FilterMgr APIs for transaction support
        //

#pragma warning(push)
#pragma warning(disable:4055) // type cast from data pointer to function pointer
        MiniSpyData.PFltSetTransactionContext = (PFLT_SET_TRANSACTION_CONTEXT) FltGetRoutineAddress( "FltSetTransactionContext" );
        MiniSpyData.PFltGetTransactionContext = (PFLT_GET_TRANSACTION_CONTEXT) FltGetRoutineAddress( "FltGetTransactionContext" );
        MiniSpyData.PFltEnlistInTransaction = (PFLT_ENLIST_IN_TRANSACTION) FltGetRoutineAddress( "FltEnlistInTransaction" );
#pragma warning(pop)

#endif

        //
        // Read the custom parameters for MiniSpy from the registry
        //

        SpyReadDriverParameters(RegistryPath);

        //
        //  Now that our global configuration is complete, register with FltMgr.
        //

        status = FltRegisterFilter( DriverObject,
                                    &FilterRegistration,
                                    &MiniSpyData.Filter );

        if (!NT_SUCCESS( status )) {

           leave;
        }


        status  = FltBuildDefaultSecurityDescriptor( &sd,
                                                     FLT_PORT_ALL_ACCESS );

        if (!NT_SUCCESS( status )) {
            leave;
        }

        RtlInitUnicodeString( &uniString, MINISPY_PORT_NAME );

        InitializeObjectAttributes( &oa,
                                    &uniString,
                                    OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                    NULL,
                                    sd );

        status = FltCreateCommunicationPort( MiniSpyData.Filter,
                                             &MiniSpyData.ServerPort,
                                             &oa,
                                             NULL,
                                             SpyConnect,
                                             SpyDisconnect,
                                             SpyMessage,
                                             1 );

        FltFreeSecurityDescriptor( sd );

        if (!NT_SUCCESS( status )) {
            leave;
        }

        //
        //  We are now ready to start filtering
        //

        status = FltStartFiltering( MiniSpyData.Filter );

    } finally {

        if (!NT_SUCCESS( status ) ) {

             if (NULL != MiniSpyData.ServerPort) {
                 FltCloseCommunicationPort( MiniSpyData.ServerPort );
             }

             if (NULL != MiniSpyData.Filter) {
                 FltUnregisterFilter( MiniSpyData.Filter );
             }

             ExDeleteNPagedLookasideList( &MiniSpyData.FreeBufferList );
        }
    }

    return status;
}

NTSTATUS
SpyConnect(
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
    )
/*++

Routine Description

    This is called when user-mode connects to the server
    port - to establish a connection

Arguments

    ClientPort - This is the pointer to the client port that
        will be used to send messages from the filter.
    ServerPortCookie - unused
    ConnectionContext - unused
    SizeofContext   - unused
    ConnectionCookie - unused

Return Value

    STATUS_SUCCESS - to accept the connection
--*/
{

    PAGED_CODE();

    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext);
    UNREFERENCED_PARAMETER( ConnectionCookie );

    FLT_ASSERT( MiniSpyData.ClientPort == NULL );
    MiniSpyData.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}


VOID
SpyDisconnect(
    _In_opt_ PVOID ConnectionCookie
   )
/*++

Routine Description

    This is called when the connection is torn-down. We use it to close our handle to the connection

Arguments

    ConnectionCookie - unused

Return value

    None
--*/
{

    PAGED_CODE();

    UNREFERENCED_PARAMETER( ConnectionCookie );

    //
    //  Close our handle
    //

    FltCloseClientPort( MiniSpyData.Filter, &MiniSpyData.ClientPort );
}

NTSTATUS
SpyFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is called when a request has been made to unload the filter.  Unload
    requests from the Operation System (ex: "sc stop minispy" can not be
    failed.  Other unload requests may be failed.

    You can disallow OS unload request by setting the
    FLTREGFL_DO_NOT_SUPPORT_SERVICE_STOP flag in the FLT_REGISTARTION
    structure.

Arguments:

    Flags - Flags pertinent to this operation

Return Value:

    Always success

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    //
    //  Close the server port. This will stop new connections.
    //

    FltCloseCommunicationPort( MiniSpyData.ServerPort );

    FltUnregisterFilter( MiniSpyData.Filter );

    SpyEmptyOutputBufferList();
    ExDeleteNPagedLookasideList( &MiniSpyData.FreeBufferList );

    return STATUS_SUCCESS;
}


NTSTATUS
SpyQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This allows our filter to be manually detached from a volume.

Arguments:

    FltObjects - Contains pointer to relevant objects for this operation.
        Note that the FileObject field will always be NULL.

    Flags - Flags pertinent to this operation

Return Value:

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    PAGED_CODE();
    return STATUS_SUCCESS;
}


NTSTATUS
SpyMessage (
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
/*++

Routine Description:

    This is called whenever a user mode application wishes to communicate
    with this minifilter.

Arguments:

    ConnectionCookie - unused

    OperationCode - An identifier describing what type of message this
        is.  These codes are defined by the MiniFilter.
    InputBuffer - A buffer containing input data, can be NULL if there
        is no input data.
    InputBufferSize - The size in bytes of the InputBuffer.
    OutputBuffer - A buffer provided by the application that originated
        the communication in which to store data to be returned to this
        application.
    OutputBufferSize - The size in bytes of the OutputBuffer.
    ReturnOutputBufferSize - The size in bytes of meaningful data
        returned in the OutputBuffer.

Return Value:

    Returns the status of processing the message.

--*/
{
    MINISPY_COMMAND command;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER( ConnectionCookie );

    //
    //                      **** PLEASE READ ****
    //
    //  The INPUT and OUTPUT buffers are raw user mode addresses.  The filter
    //  manager has already done a ProbedForRead (on InputBuffer) and
    //  ProbedForWrite (on OutputBuffer) which guarentees they are valid
    //  addresses based on the access (user mode vs. kernel mode).  The
    //  minifilter does not need to do their own probe.
    //
    //  The filter manager is NOT doing any alignment checking on the pointers.
    //  The minifilter must do this themselves if they care (see below).
    //
    //  The minifilter MUST continue to use a try/except around any access to
    //  these buffers.
    //

    if ((InputBuffer != NULL) &&
        (InputBufferSize >= (FIELD_OFFSET(COMMAND_MESSAGE,Command) +
                             sizeof(MINISPY_COMMAND)))) {

        try  {

            //
            //  Probe and capture input message: the message is raw user mode
            //  buffer, so need to protect with exception handler
            //

            command = ((PCOMMAND_MESSAGE) InputBuffer)->Command;

        } except (SpyExceptionFilter( GetExceptionInformation(), TRUE )) {
        
            return GetExceptionCode();
        }

        switch (command) {

            case GetMiniSpyLog:

                //
                //  Return as many log records as can fit into the OutputBuffer
                //

                if ((OutputBuffer == NULL) || (OutputBufferSize == 0)) {

                    status = STATUS_INVALID_PARAMETER;
                    break;
                }

                //
                //  We want to validate that the given buffer is POINTER
                //  aligned.  But if this is a 64bit system and we want to
                //  support 32bit applications we need to be careful with how
                //  we do the check.  Note that the way SpyGetLog is written
                //  it actually does not care about alignment but we are
                //  demonstrating how to do this type of check.
                //

#if defined(_WIN64)

                if (IoIs32bitProcess( NULL )) {

                    //
                    //  Validate alignment for the 32bit process on a 64bit
                    //  system
                    //

                    if (!IS_ALIGNED(OutputBuffer,sizeof(ULONG))) {

                        status = STATUS_DATATYPE_MISALIGNMENT;
                        break;
                    }

                } else {

#endif

                    if (!IS_ALIGNED(OutputBuffer,sizeof(PVOID))) {

                        status = STATUS_DATATYPE_MISALIGNMENT;
                        break;
                    }

#if defined(_WIN64)

                }

#endif

                //
                //  Get the log record.
                //

                status = SpyGetLog( OutputBuffer,
                                    OutputBufferSize,
                                    ReturnOutputBufferLength );
                break;


            case GetMiniSpyVersion:

                //
                //  Return version of the MiniSpy filter driver.  Verify
                //  we have a valid user buffer including valid
                //  alignment
                //

                if ((OutputBufferSize < sizeof( MINISPYVER )) ||
                    (OutputBuffer == NULL)) {

                    status = STATUS_INVALID_PARAMETER;
                    break;
                }

                //
                //  Validate Buffer alignment.  If a minifilter cares about
                //  the alignment value of the buffer pointer they must do
                //  this check themselves.  Note that a try/except will not
                //  capture alignment faults.
                //

                if (!IS_ALIGNED(OutputBuffer,sizeof(ULONG))) {

                    status = STATUS_DATATYPE_MISALIGNMENT;
                    break;
                }

                //
                //  Protect access to raw user-mode output buffer with an
                //  exception handler
                //

                try {

                    ((PMINISPYVER)OutputBuffer)->Major = MINISPY_MAJ_VERSION;
                    ((PMINISPYVER)OutputBuffer)->Minor = MINISPY_MIN_VERSION;

                } except (SpyExceptionFilter( GetExceptionInformation(), TRUE )) {

                      return GetExceptionCode();
                }

                *ReturnOutputBufferLength = sizeof( MINISPYVER );
                status = STATUS_SUCCESS;
                break;

            default:
                status = STATUS_INVALID_PARAMETER;
                break;
        }

    } else {

        status = STATUS_INVALID_PARAMETER;
    }

    return status;
}


//---------------------------------------------------------------------------
//              Operation filtering routines
//---------------------------------------------------------------------------

/* GO : helper function custom */

static __forceinline VOID LogProc(_In_ PFLT_CALLBACK_DATA Data, _In_ const char* tag)
{
    ULONG pid = FltGetRequestorProcessId(Data);
    HANDLE tid = PsGetCurrentThreadId();
    DbgPrint("[NPFS][%s] pid=%lu tid=%p\n", tag, pid, tid);
}


static __forceinline PVOID GetSysBufFromWrite(_Inout_ PFLT_CALLBACK_DATA Data)
{
    PVOID usr = Data->Iopb->Parameters.Write.WriteBuffer;
    if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER)) return usr;
    if (Data->Iopb->Parameters.Write.MdlAddress)
        return MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority);

    // MDL 없으면 잠금 후 재시도
    FltLockUserBuffer(Data);
    if (Data->Iopb->Parameters.Write.MdlAddress)
        return MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority);
    return NULL;
}

static __forceinline PVOID GetSysBufFromRead(_Inout_ PFLT_CALLBACK_DATA Data)
{
    PVOID usr = Data->Iopb->Parameters.Read.ReadBuffer;
    if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER)) return usr;
    if (Data->Iopb->Parameters.Read.MdlAddress)
        return MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress, NormalPagePriority);
    return NULL; // READ는 Post에서 보통 MDL이 잡혀있음
}

static VOID DumpString(_In_reads_bytes_(len) const UCHAR* p, _In_ ULONG len, _In_ ULONG max)
{
    ULONG n = (len < max ? len : max);
    CHAR buf[257] = { 0 };
    ULONG j = 0;

    for (ULONG i = 0; i < n && j < 256; i++) {
        if (p[i] >= 0x20 && p[i] <= 0x7E)
            buf[j++] = (CHAR)p[i];
        else
            buf[j++] = '.';
    }
    buf[j] = '\0';

    DbgPrint("[NPFS][ASCII] %s\n", buf);
}


static
BOOLEAN
IsNpfsVolume(_In_ PFLT_VOLUME Volume)
{
    NTSTATUS status;
    FLT_FILESYSTEM_TYPE fsType = FLT_FSTYPE_UNKNOWN ;
	status = FltGetFileSystemType(Volume, &fsType);
    
    return (fsType == FLT_FSTYPE_NPFS);
}

EXTERN_C DECLSPEC_IMPORT
UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

static __forceinline BOOLEAN IsPythonProc(_In_ PFLT_CALLBACK_DATA Data)
{
    PEPROCESS proc = FltGetRequestorProcess(Data);
    if (!proc) return FALSE;

    const UCHAR* img = PsGetProcessImageFileName(proc);
    if (!img) return FALSE;

    // PsGetProcessImageFileName → 항상 짧은 exe 이름만 반환 (예: "python.exe")
	
    if (_stricmp((const char*)img, "python.exe") == 0)
    {
        DbgPrint("[IsPython] Process Image: %s\n", img);
        return TRUE;
    }

    return FALSE;
}

FLT_PREOP_CALLBACK_STATUS
SpyPreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
   
    UNREFERENCED_PARAMETER(CompletionContext);
	

    if (!IsNpfsVolume(FltObjects->Volume)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    const UCHAR mj = Data->Iopb->MajorFunction;


    if (mj == IRP_MJ_WRITE) {
        if (!IsPythonProc(Data)) {
            // python.exe가 아니면 무시
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        ULONG len = Data->Iopb->Parameters.Write.Length;

        // 커널 모드 요청, 페이징 I/O, 길이가 0인 요청은 무시
        if (len == 0 ||
            FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ||
            Data->RequestorMode == KernelMode) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        
        if (!FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) &&
            Data->Iopb->Parameters.Write.MdlAddress == NULL) {
            FltLockUserBuffer(Data); // 실패해도 크래시 아님; Post에서 대안 처리
        }

        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }


    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


#define LOG_PREVIEW_MAX  512

typedef struct _BUF_VIEW {
    PUCHAR  Ptr;
    ULONG   Size;
    BOOLEAN NeedFree;
} BUF_VIEW;

__forceinline VOID ReleaseBufView(_Inout_ BUF_VIEW* v)
{
    if (v->NeedFree && v->Ptr) ExFreePoolWithTag(v->Ptr, 'gnPN');
    v->Ptr = NULL; v->Size = 0; v->NeedFree = FALSE;
}

// WRITE 경로용: SystemBuffer → MDL → (없으면) Probe + 임시복사
__forceinline VOID AcquireWriteView(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    ULONG wantBytes,
    _Out_   BUF_VIEW* out
) {
    RtlZeroMemory(out, sizeof(*out));

    // 1) SystemBuffer
    if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER)) {
        out->Ptr = (PUCHAR)Data->Iopb->Parameters.Write.WriteBuffer;
        out->Size = wantBytes;
        return;
    }
    // 2) MDL
    if (Data->Iopb->Parameters.Write.MdlAddress) {
        PUCHAR p = (PUCHAR)MmGetSystemAddressForMdlSafe(
            Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority);
        if (p) {
            out->Ptr = p;
            out->Size = wantBytes;
            return;
        }
    }
    // 3) 유저 버퍼 → PASSIVE에서 안전 복사(미리보기 길이만)
    __try {
        ProbeForRead(Data->Iopb->Parameters.Write.WriteBuffer, wantBytes, 1);
        PUCHAR tmp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, wantBytes, 'gnPN');
        if (tmp) {
            RtlCopyMemory(tmp, Data->Iopb->Parameters.Write.WriteBuffer, wantBytes);
            out->Ptr = tmp; out->Size = wantBytes; out->NeedFree = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        out->Ptr = NULL; out->Size = 0; out->NeedFree = FALSE;
    }
}



static FLT_POSTOP_CALLBACK_STATUS
PostWrite_WhenSafe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!NT_SUCCESS(Data->IoStatus.Status))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    ULONG wrote = (ULONG)Data->IoStatus.Information;
    if (wrote == 0)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    UNICODE_STRING name = FltObjects->FileObject->FileName;

    // 미리보기 길이 제한
    ULONG want = (wrote < LOG_PREVIEW_MAX) ? wrote : LOG_PREVIEW_MAX;

    BUF_VIEW v;
    AcquireWriteView(Data, want, &v);

    LogProc(Data, "WRITE (PostOp)");
    DbgPrint("[NPFS][WRITE-POST] pipename=%wZ len=%lu%s\n",
        name, wrote, v.Ptr ? "" : " (no-buf)");

    if (v.Ptr && want) {
        DbgPrint("[NPFS][STR] preview=%luB first=%02X\n", want, v.Ptr[0]);
        DumpString((const UCHAR*)v.Ptr, want, LOG_PREVIEW_MAX);
    }

    ReleaseBufView(&v);
    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_POSTOP_CALLBACK_STATUS
SpyPostOperationCallback (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    //UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    // 작업이 성공적으로 완료되었는지 확인
    if (!NT_SUCCESS(Data->IoStatus.Status)) 
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    const UCHAR mj = Data->Iopb->MajorFunction;
    //UNICODE_STRING name = FltObjects->FileObject->FileName;

    

    if (mj == IRP_MJ_WRITE) 
    {
        /* 방법 1 */
        /* ULONG writeLength = (ULONG)Data->IoStatus.Information; // 실제 쓰여진 길이
        PVOID sysBuffer = NULL;

        if (writeLength == 0) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        sysBuffer = GetSysBufFromWrite(Data);


        LogProc(Data, "WRITE (PostOp)");
        if (sysBuffer && writeLength > 0) {

            DbgPrint("[NPFS][WRITE-POST] pipename=%wZ len=%lu first=%02X\n",name, writeLength, ((PUCHAR)sysBuffer)[0]);
            DumpString((const UCHAR*)sysBuffer, writeLength, 256);
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING; */

    FLT_POSTOP_CALLBACK_STATUS safeStatus = FLT_POSTOP_FINISHED_PROCESSING;
    /* 방법 2 : when-safe 함수 */
        if (FltDoCompletionProcessingWhenSafe(
            Data, FltObjects, CompletionContext, Flags,
            PostWrite_WhenSafe,  // 아래 함수
            &safeStatus
        ))
        {
            return safeStatus;
    }
    }
    return FLT_POSTOP_FINISHED_PROCESSING;

}


NTSTATUS
SpyEnlistInTransaction (
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
/*++

Routine Description

    Minispy calls this function to enlist in a transaction of interest. 

Arguments

    FltObjects - Contains parameters required to enlist in a transaction.

Return value

    Returns STATUS_SUCCESS if we were able to successfully enlist in a new transcation or if we
    were already enlisted in the transaction. Returns an appropriate error code on a failure.
    
--*/
{

#if MINISPY_VISTA

    PMINISPY_TRANSACTION_CONTEXT transactionContext = NULL;
    PMINISPY_TRANSACTION_CONTEXT oldTransactionContext = NULL;
    PRECORD_LIST recordList;
    NTSTATUS status;
    static ULONG Sequence=1;

    //
    //  This code is only built in the Vista environment, but
    //  we need to ensure this binary still runs down-level.  Return
    //  at this point if the transaction dynamic imports were not found.
    //
    //  If we find FltGetTransactionContext, we assume the other
    //  transaction APIs are also present.
    //

    if (NULL == MiniSpyData.PFltGetTransactionContext) {

        return STATUS_SUCCESS;
    }

    //
    //  Try to get our context for this transaction. If we get
    //  one we have already enlisted in this transaction.
    //

    status = (*MiniSpyData.PFltGetTransactionContext)( FltObjects->Instance,
                                                       FltObjects->Transaction,
                                                       &transactionContext );

    if (NT_SUCCESS( status )) {

        // 
        //  Check if we have already enlisted in the transaction. 
        //

        if (FlagOn(transactionContext->Flags, MINISPY_ENLISTED_IN_TRANSACTION)) {

            //
            //  FltGetTransactionContext puts a reference on the context. Release
            //  that now and return success.
            //
            
            FltReleaseContext( transactionContext );
            return STATUS_SUCCESS;
        }

        //
        //  If we have not enlisted then we need to try and enlist in the transaction.
        //
        
        goto ENLIST_IN_TRANSACTION;
    }

    //
    //  If the context does not exist create a new one, else return the error
    //  status to the caller.
    //

    if (status != STATUS_NOT_FOUND) {

        return status;
    }

    //
    //  Allocate a transaction context.
    //

    status = FltAllocateContext( FltObjects->Filter,
                                 FLT_TRANSACTION_CONTEXT,
                                 sizeof(MINISPY_TRANSACTION_CONTEXT),
                                 PagedPool,
                                 &transactionContext );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    //
    //  Set the context into the transaction
    //

    RtlZeroMemory(transactionContext, sizeof(MINISPY_TRANSACTION_CONTEXT));
    transactionContext->Count = Sequence++;

    FLT_ASSERT( MiniSpyData.PFltSetTransactionContext );

    status = (*MiniSpyData.PFltSetTransactionContext)( FltObjects->Instance,
                                                       FltObjects->Transaction,
                                                       FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                                       transactionContext,
                                                       &oldTransactionContext );

    if (!NT_SUCCESS( status )) {

        FltReleaseContext( transactionContext );    //this will free the context

        if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

            return status;
        }

        FLT_ASSERT(oldTransactionContext != NULL);
        
        if (FlagOn(oldTransactionContext->Flags, MINISPY_ENLISTED_IN_TRANSACTION)) {

            //
            //  If this context is already enlisted then release the reference
            //  which FltSetTransactionContext put on it and return success.
            //
            
            FltReleaseContext( oldTransactionContext );
            return STATUS_SUCCESS;
        }

        //
        //  If we found an existing transaction then we should try and
        //  enlist in it. There is a race here in which the thread 
        //  which actually set the transaction context may fail to 
        //  enlist in the transaction and delete it later. It might so
        //  happen that we picked up a reference to that context here
        //  and successfully enlisted in that transaction. For now
        //  we have chosen to ignore this scenario.
        //

        //
        //  If we are not enlisted then assign the right transactionContext
        //  and attempt enlistment.
        //

        transactionContext = oldTransactionContext;            
    }

ENLIST_IN_TRANSACTION: 

    //
    //  Enlist on this transaction for notifications.
    //

    FLT_ASSERT( MiniSpyData.PFltEnlistInTransaction );

    status = (*MiniSpyData.PFltEnlistInTransaction)( FltObjects->Instance,
                                                     FltObjects->Transaction,
                                                     transactionContext,
                                                     FLT_MAX_TRANSACTION_NOTIFICATIONS );

    //
    //  If the enlistment failed we might have to delete the context and remove
    //  our count.
    //

    if (!NT_SUCCESS( status )) {

        //
        //  If the error is that we are already enlisted then we do not need
        //  to delete the context. Otherwise we have to delete the context
        //  before releasing our reference.
        //
        
        if (status == STATUS_FLT_ALREADY_ENLISTED) {

            status = STATUS_SUCCESS;

        } else {

            //
            //  It is worth noting that only the first caller of
            //  FltDeleteContext will remove the reference added by
            //  filter manager when the context was set.
            //
            
            FltDeleteContext( transactionContext );
        }
        
        FltReleaseContext( transactionContext );
        return status;
    }

    //
    //  Set the flag so that future enlistment efforts know that we
    //  successfully enlisted in the transaction.
    //

    SetFlagInterlocked( &transactionContext->Flags, MINISPY_ENLISTED_IN_TRANSACTION );
    
    //
    //  The operation succeeded, remove our count
    //

    FltReleaseContext( transactionContext );

    //
    //  Log a record that a new transaction has started.
    //

    recordList = SpyNewRecord();

    if (recordList) {

        SpyLogTransactionNotify( FltObjects, recordList, 0 );

        //
        //  Send the logged information to the user service.
        //

        SpyLog( recordList );
    }

#endif // MINISPY_VISTA

    return STATUS_SUCCESS;
}


#if MINISPY_VISTA

NTSTATUS
SpyKtmNotificationCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CONTEXT TransactionContext,
    _In_ ULONG TransactionNotification
    )
{
    PRECORD_LIST recordList;

    UNREFERENCED_PARAMETER( TransactionContext );

    //
    //  Try and get a log record
    //

    recordList = SpyNewRecord();

    if (recordList) {

        SpyLogTransactionNotify( FltObjects, recordList, TransactionNotification );

        //
        //  Send the logged information to the user service.
        //

        SpyLog( recordList );
    }

    return STATUS_SUCCESS;
}

#endif // MINISPY_VISTA

VOID
SpyDeleteTxfContext (
    _Inout_ PMINISPY_TRANSACTION_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
{
    UNREFERENCED_PARAMETER( Context );
    UNREFERENCED_PARAMETER( ContextType );

    FLT_ASSERT(FLT_TRANSACTION_CONTEXT == ContextType);
    FLT_ASSERT(Context->Count != 0);
}


LONG
SpyExceptionFilter (
    _In_ PEXCEPTION_POINTERS ExceptionPointer,
    _In_ BOOLEAN AccessingUserBuffer
    )
/*++

Routine Description:

    Exception filter to catch errors touching user buffers.

Arguments:

    ExceptionPointer - The exception record.

    AccessingUserBuffer - If TRUE, overrides FsRtlIsNtStatusExpected to allow
                          the caller to munge the error to a desired status.

Return Value:

    EXCEPTION_EXECUTE_HANDLER - If the exception handler should be run.

    EXCEPTION_CONTINUE_SEARCH - If a higher exception handler should take care of
                                this exception.

--*/
{
    NTSTATUS Status;

    Status = ExceptionPointer->ExceptionRecord->ExceptionCode;

    //
    //  Certain exceptions shouldn't be dismissed within the namechanger filter
    //  unless we're touching user memory.
    //

    if (!FsRtlIsNtstatusExpected( Status ) &&
        !AccessingUserBuffer) {

        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_EXECUTE_HANDLER;
}


