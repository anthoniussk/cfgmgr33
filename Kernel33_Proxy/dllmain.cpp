#include <Windows.h>

typedef HMODULE (*fpmyLoadPackagedLibrary)(LPCWSTR, DWORD);

#pragma region Proxy
struct kernel32_dll {
	HMODULE dll;
	FARPROC oAcquireSRWLockExclusive;
	FARPROC oAcquireSRWLockShared;
	FARPROC oActivateActCtx;
	FARPROC oActivateActCtxWorker;
	FARPROC oAddAtomA;
	FARPROC oAddAtomW;
	FARPROC oAddConsoleAliasA;
	FARPROC oAddConsoleAliasW;
	FARPROC oAddDllDirectory;
	FARPROC oAddIntegrityLabelToBoundaryDescriptor;
	FARPROC oAddLocalAlternateComputerNameA;
	FARPROC oAddLocalAlternateComputerNameW;
	FARPROC oAddRefActCtx;
	FARPROC oAddRefActCtxWorker;
	FARPROC oAddResourceAttributeAce;
	FARPROC oAddSIDToBoundaryDescriptor;
	FARPROC oAddScopedPolicyIDAce;
	FARPROC oAddSecureMemoryCacheCallback;
	FARPROC oAddVectoredContinueHandler;
	FARPROC oAddVectoredExceptionHandler;
	FARPROC oAdjustCalendarDate;
	FARPROC oAllocConsole;
	FARPROC oAllocateUserPhysicalPages;
	FARPROC oAllocateUserPhysicalPagesNuma;
	FARPROC oAppPolicyGetClrCompat;
	FARPROC oAppPolicyGetCreateFileAccess;
	FARPROC oAppPolicyGetLifecycleManagement;
	FARPROC oAppPolicyGetMediaFoundationCodecLoading;
	FARPROC oAppPolicyGetProcessTerminationMethod;
	FARPROC oAppPolicyGetShowDeveloperDiagnostic;
	FARPROC oAppPolicyGetThreadInitializationType;
	FARPROC oAppPolicyGetWindowingModel;
	FARPROC oAppXGetOSMaxVersionTested;
	FARPROC oApplicationRecoveryFinished;
	FARPROC oApplicationRecoveryInProgress;
	FARPROC oAreFileApisANSI;
	FARPROC oAssignProcessToJobObject;
	FARPROC oAttachConsole;
	FARPROC oBackupRead;
	FARPROC oBackupSeek;
	FARPROC oBackupWrite;
	FARPROC oBaseCheckAppcompatCache;
	FARPROC oBaseCheckAppcompatCacheEx;
	FARPROC oBaseCheckAppcompatCacheExWorker;
	FARPROC oBaseCheckAppcompatCacheWorker;
	FARPROC oBaseCheckElevation;
	FARPROC oBaseCleanupAppcompatCacheSupport;
	FARPROC oBaseCleanupAppcompatCacheSupportWorker;
	FARPROC oBaseDestroyVDMEnvironment;
	FARPROC oBaseDllReadWriteIniFile;
	FARPROC oBaseDumpAppcompatCache;
	FARPROC oBaseDumpAppcompatCacheWorker;
	FARPROC oBaseElevationPostProcessing;
	FARPROC oBaseFlushAppcompatCache;
	FARPROC oBaseFlushAppcompatCacheWorker;
	FARPROC oBaseFormatObjectAttributes;
	FARPROC oBaseFormatTimeOut;
	FARPROC oBaseFreeAppCompatDataForProcessWorker;
	FARPROC oBaseGenerateAppCompatData;
	FARPROC oBaseGetNamedObjectDirectory;
	FARPROC oBaseInitAppcompatCacheSupport;
	FARPROC oBaseInitAppcompatCacheSupportWorker;
	FARPROC oBaseIsAppcompatInfrastructureDisabled;
	FARPROC oBaseIsAppcompatInfrastructureDisabledWorker;
	FARPROC oBaseIsDosApplication;
	FARPROC oBaseQueryModuleData;
	FARPROC oBaseReadAppCompatDataForProcessWorker;
	FARPROC oBaseSetLastNTError;
	FARPROC oBaseThreadInitThunk;
	FARPROC oBaseUpdateAppcompatCache;
	FARPROC oBaseUpdateAppcompatCacheWorker;
	FARPROC oBaseUpdateVDMEntry;
	FARPROC oBaseVerifyUnicodeString;
	FARPROC oBaseWriteErrorElevationRequiredEvent;
	FARPROC oBasep8BitStringToDynamicUnicodeString;
	FARPROC oBasepAllocateActivationContextActivationBlock;
	FARPROC oBasepAnsiStringToDynamicUnicodeString;
	FARPROC oBasepAppContainerEnvironmentExtension;
	FARPROC oBasepAppXExtension;
	FARPROC oBasepCheckAppCompat;
	FARPROC oBasepCheckWebBladeHashes;
	FARPROC oBasepCheckWinSaferRestrictions;
	FARPROC oBasepConstructSxsCreateProcessMessage;
	FARPROC oBasepCopyEncryption;
	FARPROC oBasepFreeActivationContextActivationBlock;
	FARPROC oBasepFreeAppCompatData;
	FARPROC oBasepGetAppCompatData;
	FARPROC oBasepGetComputerNameFromNtPath;
	FARPROC oBasepGetExeArchType;
	FARPROC oBasepInitAppCompatData;
	FARPROC oBasepIsProcessAllowed;
	FARPROC oBasepMapModuleHandle;
	FARPROC oBasepNotifyLoadStringResource;
	FARPROC oBasepPostSuccessAppXExtension;
	FARPROC oBasepProcessInvalidImage;
	FARPROC oBasepQueryAppCompat;
	FARPROC oBasepQueryModuleChpeSettings;
	FARPROC oBasepReleaseAppXContext;
	FARPROC oBasepReleaseSxsCreateProcessUtilityStruct;
	FARPROC oBasepReportFault;
	FARPROC oBasepSetFileEncryptionCompression;
	FARPROC oBeep;
	FARPROC oBeginUpdateResourceA;
	FARPROC oBeginUpdateResourceW;
	FARPROC oBindIoCompletionCallback;
	FARPROC oBuildCommDCBA;
	FARPROC oBuildCommDCBAndTimeoutsA;
	FARPROC oBuildCommDCBAndTimeoutsW;
	FARPROC oBuildCommDCBW;
	FARPROC oCallNamedPipeA;
	FARPROC oCallNamedPipeW;
	FARPROC oCallbackMayRunLong;
	FARPROC oCancelDeviceWakeupRequest;
	FARPROC oCancelIo;
	FARPROC oCancelIoEx;
	FARPROC oCancelSynchronousIo;
	FARPROC oCancelThreadpoolIo;
	FARPROC oCancelTimerQueueTimer;
	FARPROC oCancelWaitableTimer;
	FARPROC oCeipIsOptedIn;
	FARPROC oChangeTimerQueueTimer;
	FARPROC oCheckAllowDecryptedRemoteDestinationPolicy;
	FARPROC oCheckElevation;
	FARPROC oCheckElevationEnabled;
	FARPROC oCheckForReadOnlyResource;
	FARPROC oCheckForReadOnlyResourceFilter;
	FARPROC oCheckNameLegalDOS8Dot3A;
	FARPROC oCheckNameLegalDOS8Dot3W;
	FARPROC oCheckRemoteDebuggerPresent;
	FARPROC oCheckTokenCapability;
	FARPROC oCheckTokenMembershipEx;
	FARPROC oClearCommBreak;
	FARPROC oClearCommError;
	FARPROC oCloseConsoleHandle;
	FARPROC oCloseHandle;
	FARPROC oClosePackageInfo;
	FARPROC oClosePrivateNamespace;
	FARPROC oCloseProfileUserMapping;
	FARPROC oClosePseudoConsole;
	FARPROC oCloseState;
	FARPROC oCloseThreadpool;
	FARPROC oCloseThreadpoolCleanupGroup;
	FARPROC oCloseThreadpoolCleanupGroupMembers;
	FARPROC oCloseThreadpoolIo;
	FARPROC oCloseThreadpoolTimer;
	FARPROC oCloseThreadpoolWait;
	FARPROC oCloseThreadpoolWork;
	FARPROC oCmdBatNotification;
	FARPROC oCommConfigDialogA;
	FARPROC oCommConfigDialogW;
	FARPROC oCompareCalendarDates;
	FARPROC oCompareFileTime;
	FARPROC oCompareStringA;
	FARPROC oCompareStringEx;
	FARPROC oCompareStringOrdinal;
	FARPROC oCompareStringW;
	FARPROC oConnectNamedPipe;
	FARPROC oConsoleMenuControl;
	FARPROC oContinueDebugEvent;
	FARPROC oConvertCalDateTimeToSystemTime;
	FARPROC oConvertDefaultLocale;
	FARPROC oConvertFiberToThread;
	FARPROC oConvertNLSDayOfWeekToWin32DayOfWeek;
	FARPROC oConvertSystemTimeToCalDateTime;
	FARPROC oConvertThreadToFiber;
	FARPROC oConvertThreadToFiberEx;
	FARPROC oCopyContext;
	FARPROC oCopyFile2;
	FARPROC oCopyFileA;
	FARPROC oCopyFileExA;
	FARPROC oCopyFileExW;
	FARPROC oCopyFileTransactedA;
	FARPROC oCopyFileTransactedW;
	FARPROC oCopyFileW;
	FARPROC oCopyLZFile;
	FARPROC oCreateActCtxA;
	FARPROC oCreateActCtxW;
	FARPROC oCreateActCtxWWorker;
	FARPROC oCreateBoundaryDescriptorA;
	FARPROC oCreateBoundaryDescriptorW;
	FARPROC oCreateConsoleScreenBuffer;
	FARPROC oCreateDirectoryA;
	FARPROC oCreateDirectoryExA;
	FARPROC oCreateDirectoryExW;
	FARPROC oCreateDirectoryTransactedA;
	FARPROC oCreateDirectoryTransactedW;
	FARPROC oCreateDirectoryW;
	FARPROC oCreateEnclave;
	FARPROC oCreateEventA;
	FARPROC oCreateEventExA;
	FARPROC oCreateEventExW;
	FARPROC oCreateEventW;
	FARPROC oCreateFiber;
	FARPROC oCreateFiberEx;
	FARPROC oCreateFile2;
	FARPROC oCreateFileA;
	FARPROC oCreateFileMappingA;
	FARPROC oCreateFileMappingFromApp;
	FARPROC oCreateFileMappingNumaA;
	FARPROC oCreateFileMappingNumaW;
	FARPROC oCreateFileMappingW;
	FARPROC oCreateFileTransactedA;
	FARPROC oCreateFileTransactedW;
	FARPROC oCreateFileW;
	FARPROC oCreateHardLinkA;
	FARPROC oCreateHardLinkTransactedA;
	FARPROC oCreateHardLinkTransactedW;
	FARPROC oCreateHardLinkW;
	FARPROC oCreateIoCompletionPort;
	FARPROC oCreateJobObjectA;
	FARPROC oCreateJobObjectW;
	FARPROC oCreateJobSet;
	FARPROC oCreateMailslotA;
	FARPROC oCreateMailslotW;
	FARPROC oCreateMemoryResourceNotification;
	FARPROC oCreateMutexA;
	FARPROC oCreateMutexExA;
	FARPROC oCreateMutexExW;
	FARPROC oCreateMutexW;
	FARPROC oCreateNamedPipeA;
	FARPROC oCreateNamedPipeW;
	FARPROC oCreatePipe;
	FARPROC oCreatePrivateNamespaceA;
	FARPROC oCreatePrivateNamespaceW;
	FARPROC oCreateProcessA;
	FARPROC oCreateProcessAsUserA;
	FARPROC oCreateProcessAsUserW;
	FARPROC oCreateProcessInternalA;
	FARPROC oCreateProcessInternalW;
	FARPROC oCreateProcessW;
	FARPROC oCreatePseudoConsole;
	FARPROC oCreateRemoteThread;
	FARPROC oCreateRemoteThreadEx;
	FARPROC oCreateSemaphoreA;
	FARPROC oCreateSemaphoreExA;
	FARPROC oCreateSemaphoreExW;
	FARPROC oCreateSemaphoreW;
	FARPROC oCreateSymbolicLinkA;
	FARPROC oCreateSymbolicLinkTransactedA;
	FARPROC oCreateSymbolicLinkTransactedW;
	FARPROC oCreateSymbolicLinkW;
	FARPROC oCreateTapePartition;
	FARPROC oCreateThread;
	FARPROC oCreateThreadpool;
	FARPROC oCreateThreadpoolCleanupGroup;
	FARPROC oCreateThreadpoolIo;
	FARPROC oCreateThreadpoolTimer;
	FARPROC oCreateThreadpoolWait;
	FARPROC oCreateThreadpoolWork;
	FARPROC oCreateTimerQueue;
	FARPROC oCreateTimerQueueTimer;
	FARPROC oCreateToolhelp32Snapshot;
	FARPROC oCreateUmsCompletionList;
	FARPROC oCreateUmsThreadContext;
	FARPROC oCreateWaitableTimerA;
	FARPROC oCreateWaitableTimerExA;
	FARPROC oCreateWaitableTimerExW;
	FARPROC oCreateWaitableTimerW;
	FARPROC oCtrlRoutine;
	FARPROC oDeactivateActCtx;
	FARPROC oDeactivateActCtxWorker;
	FARPROC oDebugActiveProcess;
	FARPROC oDebugActiveProcessStop;
	FARPROC oDebugBreak;
	FARPROC oDebugBreakProcess;
	FARPROC oDebugSetProcessKillOnExit;
	FARPROC oDecodePointer;
	FARPROC oDecodeSystemPointer;
	FARPROC oDefineDosDeviceA;
	FARPROC oDefineDosDeviceW;
	FARPROC oDelayLoadFailureHook;
	FARPROC oDeleteAtom;
	FARPROC oDeleteBoundaryDescriptor;
	FARPROC oDeleteCriticalSection;
	FARPROC oDeleteFiber;
	FARPROC oDeleteFileA;
	FARPROC oDeleteFileTransactedA;
	FARPROC oDeleteFileTransactedW;
	FARPROC oDeleteFileW;
	FARPROC oDeleteProcThreadAttributeList;
	FARPROC oDeleteSynchronizationBarrier;
	FARPROC oDeleteTimerQueue;
	FARPROC oDeleteTimerQueueEx;
	FARPROC oDeleteTimerQueueTimer;
	FARPROC oDeleteUmsCompletionList;
	FARPROC oDeleteUmsThreadContext;
	FARPROC oDeleteVolumeMountPointA;
	FARPROC oDeleteVolumeMountPointW;
	FARPROC oDequeueUmsCompletionListItems;
	FARPROC oDeviceIoControl;
	FARPROC oDisableThreadLibraryCalls;
	FARPROC oDisableThreadProfiling;
	FARPROC oDisassociateCurrentThreadFromCallback;
	FARPROC oDiscardVirtualMemory;
	FARPROC oDisconnectNamedPipe;
	FARPROC oDnsHostnameToComputerNameA;
	FARPROC oDnsHostnameToComputerNameExW;
	FARPROC oDnsHostnameToComputerNameW;
	FARPROC oDosDateTimeToFileTime;
	FARPROC oDosPathToSessionPathA;
	FARPROC oDosPathToSessionPathW;
	FARPROC oDuplicateConsoleHandle;
	FARPROC oDuplicateEncryptionInfoFileExt;
	FARPROC oDuplicateHandle;
	FARPROC oEnableThreadProfiling;
	FARPROC oEncodePointer;
	FARPROC oEncodeSystemPointer;
	FARPROC oEndUpdateResourceA;
	FARPROC oEndUpdateResourceW;
	FARPROC oEnterCriticalSection;
	FARPROC oEnterSynchronizationBarrier;
	FARPROC oEnterUmsSchedulingMode;
	FARPROC oEnumCalendarInfoA;
	FARPROC oEnumCalendarInfoExA;
	FARPROC oEnumCalendarInfoExEx;
	FARPROC oEnumCalendarInfoExW;
	FARPROC oEnumCalendarInfoW;
	FARPROC oEnumDateFormatsA;
	FARPROC oEnumDateFormatsExA;
	FARPROC oEnumDateFormatsExEx;
	FARPROC oEnumDateFormatsExW;
	FARPROC oEnumDateFormatsW;
	FARPROC oEnumLanguageGroupLocalesA;
	FARPROC oEnumLanguageGroupLocalesW;
	FARPROC oEnumResourceLanguagesA;
	FARPROC oEnumResourceLanguagesExA;
	FARPROC oEnumResourceLanguagesExW;
	FARPROC oEnumResourceLanguagesW;
	FARPROC oEnumResourceNamesA;
	FARPROC oEnumResourceNamesExA;
	FARPROC oEnumResourceNamesExW;
	FARPROC oEnumResourceNamesW;
	FARPROC oEnumResourceTypesA;
	FARPROC oEnumResourceTypesExA;
	FARPROC oEnumResourceTypesExW;
	FARPROC oEnumResourceTypesW;
	FARPROC oEnumSystemCodePagesA;
	FARPROC oEnumSystemCodePagesW;
	FARPROC oEnumSystemFirmwareTables;
	FARPROC oEnumSystemGeoID;
	FARPROC oEnumSystemGeoNames;
	FARPROC oEnumSystemLanguageGroupsA;
	FARPROC oEnumSystemLanguageGroupsW;
	FARPROC oEnumSystemLocalesA;
	FARPROC oEnumSystemLocalesEx;
	FARPROC oEnumSystemLocalesW;
	FARPROC oEnumTimeFormatsA;
	FARPROC oEnumTimeFormatsEx;
	FARPROC oEnumTimeFormatsW;
	FARPROC oEnumUILanguagesA;
	FARPROC oEnumUILanguagesW;
	FARPROC oEnumerateLocalComputerNamesA;
	FARPROC oEnumerateLocalComputerNamesW;
	FARPROC oEraseTape;
	FARPROC oEscapeCommFunction;
	FARPROC oExecuteUmsThread;
	FARPROC oExitProcess;
	FARPROC oExitThread;
	FARPROC oExitVDM;
	FARPROC oExpandEnvironmentStringsA;
	FARPROC oExpandEnvironmentStringsW;
	FARPROC oExpungeConsoleCommandHistoryA;
	FARPROC oExpungeConsoleCommandHistoryW;
	FARPROC oFatalAppExitA;
	FARPROC oFatalAppExitW;
	FARPROC oFatalExit;
	FARPROC oFileTimeToDosDateTime;
	FARPROC oFileTimeToLocalFileTime;
	FARPROC oFileTimeToSystemTime;
	FARPROC oFillConsoleOutputAttribute;
	FARPROC oFillConsoleOutputCharacterA;
	FARPROC oFillConsoleOutputCharacterW;
	FARPROC oFindActCtxSectionGuid;
	FARPROC oFindActCtxSectionGuidWorker;
	FARPROC oFindActCtxSectionStringA;
	FARPROC oFindActCtxSectionStringW;
	FARPROC oFindActCtxSectionStringWWorker;
	FARPROC oFindAtomA;
	FARPROC oFindAtomW;
	FARPROC oFindClose;
	FARPROC oFindCloseChangeNotification;
	FARPROC oFindFirstChangeNotificationA;
	FARPROC oFindFirstChangeNotificationW;
	FARPROC oFindFirstFileA;
	FARPROC oFindFirstFileExA;
	FARPROC oFindFirstFileExW;
	FARPROC oFindFirstFileNameTransactedW;
	FARPROC oFindFirstFileNameW;
	FARPROC oFindFirstFileTransactedA;
	FARPROC oFindFirstFileTransactedW;
	FARPROC oFindFirstFileW;
	FARPROC oFindFirstStreamTransactedW;
	FARPROC oFindFirstStreamW;
	FARPROC oFindFirstVolumeA;
	FARPROC oFindFirstVolumeMountPointA;
	FARPROC oFindFirstVolumeMountPointW;
	FARPROC oFindFirstVolumeW;
	FARPROC oFindNLSString;
	FARPROC oFindNLSStringEx;
	FARPROC oFindNextChangeNotification;
	FARPROC oFindNextFileA;
	FARPROC oFindNextFileNameW;
	FARPROC oFindNextFileW;
	FARPROC oFindNextStreamW;
	FARPROC oFindNextVolumeA;
	FARPROC oFindNextVolumeMountPointA;
	FARPROC oFindNextVolumeMountPointW;
	FARPROC oFindNextVolumeW;
	FARPROC oFindPackagesByPackageFamily;
	FARPROC oFindResourceA;
	FARPROC oFindResourceExA;
	FARPROC oFindResourceExW;
	FARPROC oFindResourceW;
	FARPROC oFindStringOrdinal;
	FARPROC oFindVolumeClose;
	FARPROC oFindVolumeMountPointClose;
	FARPROC oFlsAlloc;
	FARPROC oFlsFree;
	FARPROC oFlsGetValue;
	FARPROC oFlsSetValue;
	FARPROC oFlushConsoleInputBuffer;
	FARPROC oFlushFileBuffers;
	FARPROC oFlushInstructionCache;
	FARPROC oFlushProcessWriteBuffers;
	FARPROC oFlushViewOfFile;
	FARPROC oFoldStringA;
	FARPROC oFoldStringW;
	FARPROC oFormatApplicationUserModelId;
	FARPROC oFormatMessageA;
	FARPROC oFormatMessageW;
	FARPROC oFreeConsole;
	FARPROC oFreeEnvironmentStringsA;
	FARPROC oFreeEnvironmentStringsW;
	FARPROC oFreeLibrary;
	FARPROC oFreeLibraryAndExitThread;
	FARPROC oFreeLibraryWhenCallbackReturns;
	FARPROC oFreeMemoryJobObject;
	FARPROC oFreeResource;
	FARPROC oFreeUserPhysicalPages;
	FARPROC oGenerateConsoleCtrlEvent;
	FARPROC oGetACP;
	FARPROC oGetActiveProcessorCount;
	FARPROC oGetActiveProcessorGroupCount;
	FARPROC oGetAppContainerAce;
	FARPROC oGetAppContainerNamedObjectPath;
	FARPROC oGetApplicationRecoveryCallback;
	FARPROC oGetApplicationRecoveryCallbackWorker;
	FARPROC oGetApplicationRestartSettings;
	FARPROC oGetApplicationRestartSettingsWorker;
	FARPROC oGetApplicationUserModelId;
	FARPROC oGetAtomNameA;
	FARPROC oGetAtomNameW;
	FARPROC oGetBinaryType;
	FARPROC oGetBinaryTypeA;
	FARPROC oGetBinaryTypeW;
	FARPROC oGetCPInfo;
	FARPROC oGetCPInfoExA;
	FARPROC oGetCPInfoExW;
	FARPROC oGetCachedSigningLevel;
	FARPROC oGetCalendarDateFormat;
	FARPROC oGetCalendarDateFormatEx;
	FARPROC oGetCalendarDaysInMonth;
	FARPROC oGetCalendarDifferenceInDays;
	FARPROC oGetCalendarInfoA;
	FARPROC oGetCalendarInfoEx;
	FARPROC oGetCalendarInfoW;
	FARPROC oGetCalendarMonthsInYear;
	FARPROC oGetCalendarSupportedDateRange;
	FARPROC oGetCalendarWeekNumber;
	FARPROC oGetComPlusPackageInstallStatus;
	FARPROC oGetCommConfig;
	FARPROC oGetCommMask;
	FARPROC oGetCommModemStatus;
	FARPROC oGetCommProperties;
	FARPROC oGetCommState;
	FARPROC oGetCommTimeouts;
	FARPROC oGetCommandLineA;
	FARPROC oGetCommandLineW;
	FARPROC oGetCompressedFileSizeA;
	FARPROC oGetCompressedFileSizeTransactedA;
	FARPROC oGetCompressedFileSizeTransactedW;
	FARPROC oGetCompressedFileSizeW;
	FARPROC oGetComputerNameA;
	FARPROC oGetComputerNameExA;
	FARPROC oGetComputerNameExW;
	FARPROC oGetComputerNameW;
	FARPROC oGetConsoleAliasA;
	FARPROC oGetConsoleAliasExesA;
	FARPROC oGetConsoleAliasExesLengthA;
	FARPROC oGetConsoleAliasExesLengthW;
	FARPROC oGetConsoleAliasExesW;
	FARPROC oGetConsoleAliasW;
	FARPROC oGetConsoleAliasesA;
	FARPROC oGetConsoleAliasesLengthA;
	FARPROC oGetConsoleAliasesLengthW;
	FARPROC oGetConsoleAliasesW;
	FARPROC oGetConsoleCP;
	FARPROC oGetConsoleCharType;
	FARPROC oGetConsoleCommandHistoryA;
	FARPROC oGetConsoleCommandHistoryLengthA;
	FARPROC oGetConsoleCommandHistoryLengthW;
	FARPROC oGetConsoleCommandHistoryW;
	FARPROC oGetConsoleCursorInfo;
	FARPROC oGetConsoleCursorMode;
	FARPROC oGetConsoleDisplayMode;
	FARPROC oGetConsoleFontInfo;
	FARPROC oGetConsoleFontSize;
	FARPROC oGetConsoleHardwareState;
	FARPROC oGetConsoleHistoryInfo;
	FARPROC oGetConsoleInputExeNameA;
	FARPROC oGetConsoleInputExeNameW;
	FARPROC oGetConsoleInputWaitHandle;
	FARPROC oGetConsoleKeyboardLayoutNameA;
	FARPROC oGetConsoleKeyboardLayoutNameW;
	FARPROC oGetConsoleMode;
	FARPROC oGetConsoleNlsMode;
	FARPROC oGetConsoleOriginalTitleA;
	FARPROC oGetConsoleOriginalTitleW;
	FARPROC oGetConsoleOutputCP;
	FARPROC oGetConsoleProcessList;
	FARPROC oGetConsoleScreenBufferInfo;
	FARPROC oGetConsoleScreenBufferInfoEx;
	FARPROC oGetConsoleSelectionInfo;
	FARPROC oGetConsoleTitleA;
	FARPROC oGetConsoleTitleW;
	FARPROC oGetConsoleWindow;
	FARPROC oGetCurrencyFormatA;
	FARPROC oGetCurrencyFormatEx;
	FARPROC oGetCurrencyFormatW;
	FARPROC oGetCurrentActCtx;
	FARPROC oGetCurrentActCtxWorker;
	FARPROC oGetCurrentApplicationUserModelId;
	FARPROC oGetCurrentConsoleFont;
	FARPROC oGetCurrentConsoleFontEx;
	FARPROC oGetCurrentDirectoryA;
	FARPROC oGetCurrentDirectoryW;
	FARPROC oGetCurrentPackageFamilyName;
	FARPROC oGetCurrentPackageFullName;
	FARPROC oGetCurrentPackageId;
	FARPROC oGetCurrentPackageInfo;
	FARPROC oGetCurrentPackagePath;
	FARPROC oGetCurrentProcess;
	FARPROC oGetCurrentProcessId;
	FARPROC oGetCurrentProcessorNumber;
	FARPROC oGetCurrentProcessorNumberEx;
	FARPROC oGetCurrentThread;
	FARPROC oGetCurrentThreadId;
	FARPROC oGetCurrentThreadStackLimits;
	FARPROC oGetCurrentUmsThread;
	FARPROC oGetDateFormatA;
	FARPROC oGetDateFormatAWorker;
	FARPROC oGetDateFormatEx;
	FARPROC oGetDateFormatW;
	FARPROC oGetDateFormatWWorker;
	FARPROC oGetDefaultCommConfigA;
	FARPROC oGetDefaultCommConfigW;
	FARPROC oGetDevicePowerState;
	FARPROC oGetDiskFreeSpaceA;
	FARPROC oGetDiskFreeSpaceExA;
	FARPROC oGetDiskFreeSpaceExW;
	FARPROC oGetDiskFreeSpaceW;
	FARPROC oGetDiskSpaceInformationA;
	FARPROC oGetDiskSpaceInformationW;
	FARPROC oGetDllDirectoryA;
	FARPROC oGetDllDirectoryW;
	FARPROC oGetDriveTypeA;
	FARPROC oGetDriveTypeW;
	FARPROC oGetDurationFormat;
	FARPROC oGetDurationFormatEx;
	FARPROC oGetDynamicTimeZoneInformation;
	FARPROC oGetEnabledXStateFeatures;
	FARPROC oGetEncryptedFileVersionExt;
	FARPROC oGetEnvironmentStrings;
	FARPROC oGetEnvironmentStringsA;
	FARPROC oGetEnvironmentStringsW;
	FARPROC oGetEnvironmentVariableA;
	FARPROC oGetEnvironmentVariableW;
	FARPROC oGetEraNameCountedString;
	FARPROC oGetErrorMode;
	FARPROC oGetExitCodeProcess;
	FARPROC oGetExitCodeThread;
	FARPROC oGetExpandedNameA;
	FARPROC oGetExpandedNameW;
	FARPROC oGetFileAttributesA;
	FARPROC oGetFileAttributesExA;
	FARPROC oGetFileAttributesExW;
	FARPROC oGetFileAttributesTransactedA;
	FARPROC oGetFileAttributesTransactedW;
	FARPROC oGetFileAttributesW;
	FARPROC oGetFileBandwidthReservation;
	FARPROC oGetFileInformationByHandle;
	FARPROC oGetFileInformationByHandleEx;
	FARPROC oGetFileMUIInfo;
	FARPROC oGetFileMUIPath;
	FARPROC oGetFileSize;
	FARPROC oGetFileSizeEx;
	FARPROC oGetFileTime;
	FARPROC oGetFileType;
	FARPROC oGetFinalPathNameByHandleA;
	FARPROC oGetFinalPathNameByHandleW;
	FARPROC oGetFirmwareEnvironmentVariableA;
	FARPROC oGetFirmwareEnvironmentVariableExA;
	FARPROC oGetFirmwareEnvironmentVariableExW;
	FARPROC oGetFirmwareEnvironmentVariableW;
	FARPROC oGetFirmwareType;
	FARPROC oGetFullPathNameA;
	FARPROC oGetFullPathNameTransactedA;
	FARPROC oGetFullPathNameTransactedW;
	FARPROC oGetFullPathNameW;
	FARPROC oGetGeoInfoA;
	FARPROC oGetGeoInfoEx;
	FARPROC oGetGeoInfoW;
	FARPROC oGetHandleInformation;
	FARPROC oGetLargePageMinimum;
	FARPROC oGetLargestConsoleWindowSize;
	FARPROC oGetLastError;
	FARPROC oGetLocalTime;
	FARPROC oGetLocaleInfoA;
	FARPROC oGetLocaleInfoEx;
	FARPROC oGetLocaleInfoW;
	FARPROC oGetLogicalDriveStringsA;
	FARPROC oGetLogicalDriveStringsW;
	FARPROC oGetLogicalDrives;
	FARPROC oGetLogicalProcessorInformation;
	FARPROC oGetLogicalProcessorInformationEx;
	FARPROC oGetLongPathNameA;
	FARPROC oGetLongPathNameTransactedA;
	FARPROC oGetLongPathNameTransactedW;
	FARPROC oGetLongPathNameW;
	FARPROC oGetMailslotInfo;
	FARPROC oGetMaximumProcessorCount;
	FARPROC oGetMaximumProcessorGroupCount;
	FARPROC oGetMemoryErrorHandlingCapabilities;
	FARPROC oGetModuleFileNameA;
	FARPROC oGetModuleFileNameW;
	FARPROC oGetModuleHandleA;
	FARPROC oGetModuleHandleExA;
	FARPROC oGetModuleHandleExW;
	FARPROC oGetModuleHandleW;
	FARPROC oGetNLSVersion;
	FARPROC oGetNLSVersionEx;
	FARPROC oGetNamedPipeAttribute;
	FARPROC oGetNamedPipeClientComputerNameA;
	FARPROC oGetNamedPipeClientComputerNameW;
	FARPROC oGetNamedPipeClientProcessId;
	FARPROC oGetNamedPipeClientSessionId;
	FARPROC oGetNamedPipeHandleStateA;
	FARPROC oGetNamedPipeHandleStateW;
	FARPROC oGetNamedPipeInfo;
	FARPROC oGetNamedPipeServerProcessId;
	FARPROC oGetNamedPipeServerSessionId;
	FARPROC oGetNativeSystemInfo;
	FARPROC oGetNextUmsListItem;
	FARPROC oGetNextVDMCommand;
	FARPROC oGetNumaAvailableMemoryNode;
	FARPROC oGetNumaAvailableMemoryNodeEx;
	FARPROC oGetNumaHighestNodeNumber;
	FARPROC oGetNumaNodeNumberFromHandle;
	FARPROC oGetNumaNodeProcessorMask;
	FARPROC oGetNumaNodeProcessorMaskEx;
	FARPROC oGetNumaProcessorNode;
	FARPROC oGetNumaProcessorNodeEx;
	FARPROC oGetNumaProximityNode;
	FARPROC oGetNumaProximityNodeEx;
	FARPROC oGetNumberFormatA;
	FARPROC oGetNumberFormatEx;
	FARPROC oGetNumberFormatW;
	FARPROC oGetNumberOfConsoleFonts;
	FARPROC oGetNumberOfConsoleInputEvents;
	FARPROC oGetNumberOfConsoleMouseButtons;
	FARPROC oGetOEMCP;
	FARPROC oGetOverlappedResult;
	FARPROC oGetOverlappedResultEx;
	FARPROC oGetPackageApplicationIds;
	FARPROC oGetPackageFamilyName;
	FARPROC oGetPackageFullName;
	FARPROC oGetPackageId;
	FARPROC oGetPackageInfo;
	FARPROC oGetPackagePath;
	FARPROC oGetPackagePathByFullName;
	FARPROC oGetPackagesByPackageFamily;
	FARPROC oGetPhysicallyInstalledSystemMemory;
	FARPROC oGetPriorityClass;
	FARPROC oGetPrivateProfileIntA;
	FARPROC oGetPrivateProfileIntW;
	FARPROC oGetPrivateProfileSectionA;
	FARPROC oGetPrivateProfileSectionNamesA;
	FARPROC oGetPrivateProfileSectionNamesW;
	FARPROC oGetPrivateProfileSectionW;
	FARPROC oGetPrivateProfileStringA;
	FARPROC oGetPrivateProfileStringW;
	FARPROC oGetPrivateProfileStructA;
	FARPROC oGetPrivateProfileStructW;
	FARPROC oGetProcAddress;
	FARPROC oGetProcessAffinityMask;
	FARPROC oGetProcessDEPPolicy;
	FARPROC oGetProcessDefaultCpuSets;
	FARPROC oGetProcessGroupAffinity;
	FARPROC oGetProcessHandleCount;
	FARPROC oGetProcessHeap;
	FARPROC oGetProcessHeaps;
	FARPROC oGetProcessId;
	FARPROC oGetProcessIdOfThread;
	FARPROC oGetProcessInformation;
	FARPROC oGetProcessIoCounters;
	FARPROC oGetProcessMitigationPolicy;
	FARPROC oGetProcessPreferredUILanguages;
	FARPROC oGetProcessPriorityBoost;
	FARPROC oGetProcessShutdownParameters;
	FARPROC oGetProcessTimes;
	FARPROC oGetProcessVersion;
	FARPROC oGetProcessWorkingSetSize;
	FARPROC oGetProcessWorkingSetSizeEx;
	FARPROC oGetProcessorSystemCycleTime;
	FARPROC oGetProductInfo;
	FARPROC oGetProfileIntA;
	FARPROC oGetProfileIntW;
	FARPROC oGetProfileSectionA;
	FARPROC oGetProfileSectionW;
	FARPROC oGetProfileStringA;
	FARPROC oGetProfileStringW;
	FARPROC oGetQueuedCompletionStatus;
	FARPROC oGetQueuedCompletionStatusEx;
	FARPROC oGetShortPathNameA;
	FARPROC oGetShortPathNameW;
	FARPROC oGetStagedPackagePathByFullName;
	FARPROC oGetStartupInfoA;
	FARPROC oGetStartupInfoW;
	FARPROC oGetStateFolder;
	FARPROC oGetStdHandle;
	FARPROC oGetStringScripts;
	FARPROC oGetStringTypeA;
	FARPROC oGetStringTypeExA;
	FARPROC oGetStringTypeExW;
	FARPROC oGetStringTypeW;
	FARPROC oGetSystemAppDataKey;
	FARPROC oGetSystemCpuSetInformation;
	FARPROC oGetSystemDEPPolicy;
	FARPROC oGetSystemDefaultLCID;
	FARPROC oGetSystemDefaultLangID;
	FARPROC oGetSystemDefaultLocaleName;
	FARPROC oGetSystemDefaultUILanguage;
	FARPROC oGetSystemDirectoryA;
	FARPROC oGetSystemDirectoryW;
	FARPROC oGetSystemFileCacheSize;
	FARPROC oGetSystemFirmwareTable;
	FARPROC oGetSystemInfo;
	FARPROC oGetSystemPowerStatus;
	FARPROC oGetSystemPreferredUILanguages;
	FARPROC oGetSystemRegistryQuota;
	FARPROC oGetSystemTime;
	FARPROC oGetSystemTimeAdjustment;
	FARPROC oGetSystemTimeAsFileTime;
	FARPROC oGetSystemTimePreciseAsFileTime;
	FARPROC oGetSystemTimes;
	FARPROC oGetSystemWindowsDirectoryA;
	FARPROC oGetSystemWindowsDirectoryW;
	FARPROC oGetSystemWow64DirectoryA;
	FARPROC oGetSystemWow64DirectoryW;
	FARPROC oGetTapeParameters;
	FARPROC oGetTapePosition;
	FARPROC oGetTapeStatus;
	FARPROC oGetTempFileNameA;
	FARPROC oGetTempFileNameW;
	FARPROC oGetTempPathA;
	FARPROC oGetTempPathW;
	FARPROC oGetThreadContext;
	FARPROC oGetThreadDescription;
	FARPROC oGetThreadErrorMode;
	FARPROC oGetThreadGroupAffinity;
	FARPROC oGetThreadIOPendingFlag;
	FARPROC oGetThreadId;
	FARPROC oGetThreadIdealProcessorEx;
	FARPROC oGetThreadInformation;
	FARPROC oGetThreadLocale;
	FARPROC oGetThreadPreferredUILanguages;
	FARPROC oGetThreadPriority;
	FARPROC oGetThreadPriorityBoost;
	FARPROC oGetThreadSelectedCpuSets;
	FARPROC oGetThreadSelectorEntry;
	FARPROC oGetThreadTimes;
	FARPROC oGetThreadUILanguage;
	FARPROC oGetTickCount;
	FARPROC oGetTickCount64;
	FARPROC oGetTimeFormatA;
	FARPROC oGetTimeFormatAWorker;
	FARPROC oGetTimeFormatEx;
	FARPROC oGetTimeFormatW;
	FARPROC oGetTimeFormatWWorker;
	FARPROC oGetTimeZoneInformation;
	FARPROC oGetTimeZoneInformationForYear;
	FARPROC oGetUILanguageInfo;
	FARPROC oGetUmsCompletionListEvent;
	FARPROC oGetUmsSystemThreadInformation;
	FARPROC oGetUserDefaultGeoName;
	FARPROC oGetUserDefaultLCID;
	FARPROC oGetUserDefaultLangID;
	FARPROC oGetUserDefaultLocaleName;
	FARPROC oGetUserDefaultUILanguage;
	FARPROC oGetUserGeoID;
	FARPROC oGetUserPreferredUILanguages;
	FARPROC oGetVDMCurrentDirectories;
	FARPROC oGetVersion;
	FARPROC oGetVersionExA;
	FARPROC oGetVersionExW;
	FARPROC oGetVolumeInformationA;
	FARPROC oGetVolumeInformationByHandleW;
	FARPROC oGetVolumeInformationW;
	FARPROC oGetVolumeNameForVolumeMountPointA;
	FARPROC oGetVolumeNameForVolumeMountPointW;
	FARPROC oGetVolumePathNameA;
	FARPROC oGetVolumePathNameW;
	FARPROC oGetVolumePathNamesForVolumeNameA;
	FARPROC oGetVolumePathNamesForVolumeNameW;
	FARPROC oGetWindowsDirectoryA;
	FARPROC oGetWindowsDirectoryW;
	FARPROC oGetWriteWatch;
	FARPROC oGetXStateFeaturesMask;
	FARPROC oGlobalAddAtomA;
	FARPROC oGlobalAddAtomExA;
	FARPROC oGlobalAddAtomExW;
	FARPROC oGlobalAddAtomW;
	FARPROC oGlobalAlloc;
	FARPROC oGlobalCompact;
	FARPROC oGlobalDeleteAtom;
	FARPROC oGlobalFindAtomA;
	FARPROC oGlobalFindAtomW;
	FARPROC oGlobalFix;
	FARPROC oGlobalFlags;
	FARPROC oGlobalFree;
	FARPROC oGlobalGetAtomNameA;
	FARPROC oGlobalGetAtomNameW;
	FARPROC oGlobalHandle;
	FARPROC oGlobalLock;
	FARPROC oGlobalMemoryStatus;
	FARPROC oGlobalMemoryStatusEx;
	FARPROC oGlobalReAlloc;
	FARPROC oGlobalSize;
	FARPROC oGlobalUnWire;
	FARPROC oGlobalUnfix;
	FARPROC oGlobalUnlock;
	FARPROC oGlobalWire;
	FARPROC oHeap32First;
	FARPROC oHeap32ListFirst;
	FARPROC oHeap32ListNext;
	FARPROC oHeap32Next;
	FARPROC oHeapAlloc;
	FARPROC oHeapCompact;
	FARPROC oHeapCreate;
	FARPROC oHeapDestroy;
	FARPROC oHeapFree;
	FARPROC oHeapLock;
	FARPROC oHeapQueryInformation;
	FARPROC oHeapReAlloc;
	FARPROC oHeapSetInformation;
	FARPROC oHeapSize;
	FARPROC oHeapSummary;
	FARPROC oHeapUnlock;
	FARPROC oHeapValidate;
	FARPROC oHeapWalk;
	FARPROC oIdnToAscii;
	FARPROC oIdnToNameprepUnicode;
	FARPROC oIdnToUnicode;
	FARPROC oInitAtomTable;
	FARPROC oInitOnceBeginInitialize;
	FARPROC oInitOnceComplete;
	FARPROC oInitOnceExecuteOnce;
	FARPROC oInitOnceInitialize;
	FARPROC oInitializeConditionVariable;
	FARPROC oInitializeContext;
	FARPROC oInitializeContext2;
	FARPROC oInitializeCriticalSection;
	FARPROC oInitializeCriticalSectionAndSpinCount;
	FARPROC oInitializeCriticalSectionEx;
	FARPROC oInitializeEnclave;
	FARPROC oInitializeProcThreadAttributeList;
	FARPROC oInitializeSListHead;
	FARPROC oInitializeSRWLock;
	FARPROC oInitializeSynchronizationBarrier;
	FARPROC oInstallELAMCertificateInfo;
	FARPROC oInterlockedFlushSList;
	FARPROC oInterlockedPopEntrySList;
	FARPROC oInterlockedPushEntrySList;
	FARPROC oInterlockedPushListSList;
	FARPROC oInterlockedPushListSListEx;
	FARPROC oInvalidateConsoleDIBits;
	FARPROC oIsBadCodePtr;
	FARPROC oIsBadHugeReadPtr;
	FARPROC oIsBadHugeWritePtr;
	FARPROC oIsBadReadPtr;
	FARPROC oIsBadStringPtrA;
	FARPROC oIsBadStringPtrW;
	FARPROC oIsBadWritePtr;
	FARPROC oIsCalendarLeapDay;
	FARPROC oIsCalendarLeapMonth;
	FARPROC oIsCalendarLeapYear;
	FARPROC oIsDBCSLeadByte;
	FARPROC oIsDBCSLeadByteEx;
	FARPROC oIsDebuggerPresent;
	FARPROC oIsEnclaveTypeSupported;
	FARPROC oIsNLSDefinedString;
	FARPROC oIsNativeVhdBoot;
	FARPROC oIsNormalizedString;
	FARPROC oIsProcessCritical;
	FARPROC oIsProcessInJob;
	FARPROC oIsProcessorFeaturePresent;
	FARPROC oIsSystemResumeAutomatic;
	FARPROC oIsThreadAFiber;
	FARPROC oIsThreadpoolTimerSet;
	FARPROC oIsValidCalDateTime;
	FARPROC oIsValidCodePage;
	FARPROC oIsValidLanguageGroup;
	FARPROC oIsValidLocale;
	FARPROC oIsValidLocaleName;
	FARPROC oIsValidNLSVersion;
	FARPROC oIsWow64GuestMachineSupported;
	FARPROC oIsWow64Process;
	FARPROC oIsWow64Process2;
	FARPROC oK32EmptyWorkingSet;
	FARPROC oK32EnumDeviceDrivers;
	FARPROC oK32EnumPageFilesA;
	FARPROC oK32EnumPageFilesW;
	FARPROC oK32EnumProcessModules;
	FARPROC oK32EnumProcessModulesEx;
	FARPROC oK32EnumProcesses;
	FARPROC oK32GetDeviceDriverBaseNameA;
	FARPROC oK32GetDeviceDriverBaseNameW;
	FARPROC oK32GetDeviceDriverFileNameA;
	FARPROC oK32GetDeviceDriverFileNameW;
	FARPROC oK32GetMappedFileNameA;
	FARPROC oK32GetMappedFileNameW;
	FARPROC oK32GetModuleBaseNameA;
	FARPROC oK32GetModuleBaseNameW;
	FARPROC oK32GetModuleFileNameExA;
	FARPROC oK32GetModuleFileNameExW;
	FARPROC oK32GetModuleInformation;
	FARPROC oK32GetPerformanceInfo;
	FARPROC oK32GetProcessImageFileNameA;
	FARPROC oK32GetProcessImageFileNameW;
	FARPROC oK32GetProcessMemoryInfo;
	FARPROC oK32GetWsChanges;
	FARPROC oK32GetWsChangesEx;
	FARPROC oK32InitializeProcessForWsWatch;
	FARPROC oK32QueryWorkingSet;
	FARPROC oK32QueryWorkingSetEx;
	FARPROC oLCIDToLocaleName;
	FARPROC oLCMapStringA;
	FARPROC oLCMapStringEx;
	FARPROC oLCMapStringW;
	FARPROC oLZClose;
	FARPROC oLZCloseFile;
	FARPROC oLZCopy;
	FARPROC oLZCreateFileW;
	FARPROC oLZDone;
	FARPROC oLZInit;
	FARPROC oLZOpenFileA;
	FARPROC oLZOpenFileW;
	FARPROC oLZRead;
	FARPROC oLZSeek;
	FARPROC oLZStart;
	FARPROC oLeaveCriticalSection;
	FARPROC oLeaveCriticalSectionWhenCallbackReturns;
	FARPROC oLoadAppInitDlls;
	FARPROC oLoadEnclaveData;
	FARPROC oLoadLibraryA;
	FARPROC oLoadLibraryExA;
	FARPROC oLoadLibraryExW;
	FARPROC oLoadLibraryW;
	FARPROC oLoadModule;
	//FARPROC oLoadPackagedLibrary;
	fpmyLoadPackagedLibrary oLoadPackagedLibrary;
	FARPROC oLoadResource;
	FARPROC oLoadStringBaseExW;
	FARPROC oLoadStringBaseW;
	FARPROC oLocalAlloc;
	FARPROC oLocalCompact;
	FARPROC oLocalFileTimeToFileTime;
	FARPROC oLocalFileTimeToLocalSystemTime;
	FARPROC oLocalFlags;
	FARPROC oLocalFree;
	FARPROC oLocalHandle;
	FARPROC oLocalLock;
	FARPROC oLocalReAlloc;
	FARPROC oLocalShrink;
	FARPROC oLocalSize;
	FARPROC oLocalSystemTimeToLocalFileTime;
	FARPROC oLocalUnlock;
	FARPROC oLocaleNameToLCID;
	FARPROC oLocateXStateFeature;
	FARPROC oLockFile;
	FARPROC oLockFileEx;
	FARPROC oLockResource;
	FARPROC oMapUserPhysicalPages;
	FARPROC oMapUserPhysicalPagesScatter;
	FARPROC oMapViewOfFile;
	FARPROC oMapViewOfFileEx;
	FARPROC oMapViewOfFileExNuma;
	FARPROC oMapViewOfFileFromApp;
	FARPROC oModule32First;
	FARPROC oModule32FirstW;
	FARPROC oModule32Next;
	FARPROC oModule32NextW;
	FARPROC oMoveFileA;
	FARPROC oMoveFileExA;
	FARPROC oMoveFileExW;
	FARPROC oMoveFileTransactedA;
	FARPROC oMoveFileTransactedW;
	FARPROC oMoveFileW;
	FARPROC oMoveFileWithProgressA;
	FARPROC oMoveFileWithProgressW;
	FARPROC oMulDiv;
	FARPROC oMultiByteToWideChar;
	FARPROC oNeedCurrentDirectoryForExePathA;
	FARPROC oNeedCurrentDirectoryForExePathW;
	FARPROC oNlsCheckPolicy;
	FARPROC oNlsEventDataDescCreate;
	FARPROC oNlsGetCacheUpdateCount;
	FARPROC oNlsUpdateLocale;
	FARPROC oNlsUpdateSystemLocale;
	FARPROC oNlsWriteEtwEvent;
	FARPROC oNormalizeString;
	FARPROC oNotifyMountMgr;
	FARPROC oNotifyUILanguageChange;
	FARPROC oNtVdm64CreateProcessInternalW;
	FARPROC oOOBEComplete;
	FARPROC oOfferVirtualMemory;
	FARPROC oOpenConsoleW;
	FARPROC oOpenConsoleWStub;
	FARPROC oOpenEventA;
	FARPROC oOpenEventW;
	FARPROC oOpenFile;
	FARPROC oOpenFileById;
	FARPROC oOpenFileMappingA;
	FARPROC oOpenFileMappingW;
	FARPROC oOpenJobObjectA;
	FARPROC oOpenJobObjectW;
	FARPROC oOpenMutexA;
	FARPROC oOpenMutexW;
	FARPROC oOpenPackageInfoByFullName;
	FARPROC oOpenPrivateNamespaceA;
	FARPROC oOpenPrivateNamespaceW;
	FARPROC oOpenProcess;
	FARPROC oOpenProcessToken;
	FARPROC oOpenProfileUserMapping;
	FARPROC oOpenSemaphoreA;
	FARPROC oOpenSemaphoreW;
	FARPROC oOpenState;
	FARPROC oOpenStateExplicit;
	FARPROC oOpenThread;
	FARPROC oOpenThreadToken;
	FARPROC oOpenWaitableTimerA;
	FARPROC oOpenWaitableTimerW;
	FARPROC oOutputDebugStringA;
	FARPROC oOutputDebugStringW;
	FARPROC oPackageFamilyNameFromFullName;
	FARPROC oPackageFamilyNameFromId;
	FARPROC oPackageFullNameFromId;
	FARPROC oPackageIdFromFullName;
	FARPROC oPackageNameAndPublisherIdFromFamilyName;
	FARPROC oParseApplicationUserModelId;
	FARPROC oPeekConsoleInputA;
	FARPROC oPeekConsoleInputW;
	FARPROC oPeekNamedPipe;
	FARPROC oPostQueuedCompletionStatus;
	FARPROC oPowerClearRequest;
	FARPROC oPowerCreateRequest;
	FARPROC oPowerSetRequest;
	FARPROC oPrefetchVirtualMemory;
	FARPROC oPrepareTape;
	FARPROC oPrivCopyFileExW;
	FARPROC oPrivMoveFileIdentityW;
	FARPROC oProcess32First;
	FARPROC oProcess32FirstW;
	FARPROC oProcess32Next;
	FARPROC oProcess32NextW;
	FARPROC oProcessIdToSessionId;
	FARPROC oPssCaptureSnapshot;
	FARPROC oPssDuplicateSnapshot;
	FARPROC oPssFreeSnapshot;
	FARPROC oPssQuerySnapshot;
	FARPROC oPssWalkMarkerCreate;
	FARPROC oPssWalkMarkerFree;
	FARPROC oPssWalkMarkerGetPosition;
	FARPROC oPssWalkMarkerRewind;
	FARPROC oPssWalkMarkerSeek;
	FARPROC oPssWalkMarkerSeekToBeginning;
	FARPROC oPssWalkMarkerSetPosition;
	FARPROC oPssWalkMarkerTell;
	FARPROC oPssWalkSnapshot;
	FARPROC oPulseEvent;
	FARPROC oPurgeComm;
	FARPROC oQueryActCtxSettingsW;
	FARPROC oQueryActCtxSettingsWWorker;
	FARPROC oQueryActCtxW;
	FARPROC oQueryActCtxWWorker;
	FARPROC oQueryDepthSList;
	FARPROC oQueryDosDeviceA;
	FARPROC oQueryDosDeviceW;
	FARPROC oQueryFullProcessImageNameA;
	FARPROC oQueryFullProcessImageNameW;
	FARPROC oQueryIdleProcessorCycleTime;
	FARPROC oQueryIdleProcessorCycleTimeEx;
	FARPROC oQueryInformationJobObject;
	FARPROC oQueryIoRateControlInformationJobObject;
	FARPROC oQueryMemoryResourceNotification;
	FARPROC oQueryPerformanceCounter;
	FARPROC oQueryPerformanceFrequency;
	FARPROC oQueryProcessAffinityUpdateMode;
	FARPROC oQueryProcessCycleTime;
	FARPROC oQueryProtectedPolicy;
	FARPROC oQueryThreadCycleTime;
	FARPROC oQueryThreadProfiling;
	FARPROC oQueryThreadpoolStackInformation;
	FARPROC oQueryUmsThreadInformation;
	FARPROC oQueryUnbiasedInterruptTime;
	FARPROC oQueueUserAPC;
	FARPROC oQueueUserWorkItem;
	FARPROC oQuirkGetData2Worker;
	FARPROC oQuirkGetDataWorker;
	FARPROC oQuirkIsEnabled2Worker;
	FARPROC oQuirkIsEnabled3Worker;
	FARPROC oQuirkIsEnabledForPackage2Worker;
	FARPROC oQuirkIsEnabledForPackage3Worker;
	FARPROC oQuirkIsEnabledForPackage4Worker;
	FARPROC oQuirkIsEnabledForPackageWorker;
	FARPROC oQuirkIsEnabledForProcessWorker;
	FARPROC oQuirkIsEnabledWorker;
	FARPROC oRaiseException;
	FARPROC oRaiseFailFastException;
	FARPROC oRaiseInvalid16BitExeError;
	FARPROC oReOpenFile;
	FARPROC oReadConsoleA;
	FARPROC oReadConsoleInputA;
	FARPROC oReadConsoleInputExA;
	FARPROC oReadConsoleInputExW;
	FARPROC oReadConsoleInputW;
	FARPROC oReadConsoleOutputA;
	FARPROC oReadConsoleOutputAttribute;
	FARPROC oReadConsoleOutputCharacterA;
	FARPROC oReadConsoleOutputCharacterW;
	FARPROC oReadConsoleOutputW;
	FARPROC oReadConsoleW;
	FARPROC oReadDirectoryChangesExW;
	FARPROC oReadDirectoryChangesW;
	FARPROC oReadFile;
	FARPROC oReadFileEx;
	FARPROC oReadFileScatter;
	FARPROC oReadProcessMemory;
	FARPROC oReadThreadProfilingData;
	FARPROC oReclaimVirtualMemory;
	FARPROC oRegCloseKey;
	FARPROC oRegCopyTreeW;
	FARPROC oRegCreateKeyExA;
	FARPROC oRegCreateKeyExW;
	FARPROC oRegDeleteKeyExA;
	FARPROC oRegDeleteKeyExW;
	FARPROC oRegDeleteTreeA;
	FARPROC oRegDeleteTreeW;
	FARPROC oRegDeleteValueA;
	FARPROC oRegDeleteValueW;
	FARPROC oRegDisablePredefinedCacheEx;
	FARPROC oRegEnumKeyExA;
	FARPROC oRegEnumKeyExW;
	FARPROC oRegEnumValueA;
	FARPROC oRegEnumValueW;
	FARPROC oRegFlushKey;
	FARPROC oRegGetKeySecurity;
	FARPROC oRegGetValueA;
	FARPROC oRegGetValueW;
	FARPROC oRegLoadKeyA;
	FARPROC oRegLoadKeyW;
	FARPROC oRegLoadMUIStringA;
	FARPROC oRegLoadMUIStringW;
	FARPROC oRegNotifyChangeKeyValue;
	FARPROC oRegOpenCurrentUser;
	FARPROC oRegOpenKeyExA;
	FARPROC oRegOpenKeyExW;
	FARPROC oRegOpenUserClassesRoot;
	FARPROC oRegQueryInfoKeyA;
	FARPROC oRegQueryInfoKeyW;
	FARPROC oRegQueryValueExA;
	FARPROC oRegQueryValueExW;
	FARPROC oRegRestoreKeyA;
	FARPROC oRegRestoreKeyW;
	FARPROC oRegSaveKeyExA;
	FARPROC oRegSaveKeyExW;
	FARPROC oRegSetKeySecurity;
	FARPROC oRegSetValueExA;
	FARPROC oRegSetValueExW;
	FARPROC oRegUnLoadKeyA;
	FARPROC oRegUnLoadKeyW;
	FARPROC oRegisterApplicationRecoveryCallback;
	FARPROC oRegisterApplicationRestart;
	FARPROC oRegisterBadMemoryNotification;
	FARPROC oRegisterConsoleIME;
	FARPROC oRegisterConsoleOS2;
	FARPROC oRegisterConsoleVDM;
	FARPROC oRegisterWaitForInputIdle;
	FARPROC oRegisterWaitForSingleObject;
	FARPROC oRegisterWaitForSingleObjectEx;
	FARPROC oRegisterWaitUntilOOBECompleted;
	FARPROC oRegisterWowBaseHandlers;
	FARPROC oRegisterWowExec;
	FARPROC oReleaseActCtx;
	FARPROC oReleaseActCtxWorker;
	FARPROC oReleaseMutex;
	FARPROC oReleaseMutexWhenCallbackReturns;
	FARPROC oReleaseSRWLockExclusive;
	FARPROC oReleaseSRWLockShared;
	FARPROC oReleaseSemaphore;
	FARPROC oReleaseSemaphoreWhenCallbackReturns;
	FARPROC oRemoveDirectoryA;
	FARPROC oRemoveDirectoryTransactedA;
	FARPROC oRemoveDirectoryTransactedW;
	FARPROC oRemoveDirectoryW;
	FARPROC oRemoveDllDirectory;
	FARPROC oRemoveLocalAlternateComputerNameA;
	FARPROC oRemoveLocalAlternateComputerNameW;
	FARPROC oRemoveSecureMemoryCacheCallback;
	FARPROC oRemoveVectoredContinueHandler;
	FARPROC oRemoveVectoredExceptionHandler;
	FARPROC oReplaceFile;
	FARPROC oReplaceFileA;
	FARPROC oReplaceFileW;
	FARPROC oReplacePartitionUnit;
	FARPROC oRequestDeviceWakeup;
	FARPROC oRequestWakeupLatency;
	FARPROC oResetEvent;
	FARPROC oResetWriteWatch;
	FARPROC oResizePseudoConsole;
	FARPROC oResolveDelayLoadedAPI;
	FARPROC oResolveDelayLoadsFromDll;
	FARPROC oResolveLocaleName;
	FARPROC oRestoreLastError;
	FARPROC oResumeThread;
	FARPROC oRtlAddFunctionTable;
	FARPROC oRtlCaptureContext;
	FARPROC oRtlCaptureStackBackTrace;
	FARPROC oRtlCompareMemory;
	FARPROC oRtlCopyMemory;
	FARPROC oRtlDeleteFunctionTable;
	FARPROC oRtlFillMemory;
	FARPROC oRtlInstallFunctionTableCallback;
	FARPROC oRtlLookupFunctionEntry;
	FARPROC oRtlMoveMemory;
	FARPROC oRtlPcToFileHeader;
	FARPROC oRtlRaiseException;
	FARPROC oRtlRestoreContext;
	FARPROC oRtlUnwind;
	FARPROC oRtlUnwindEx;
	FARPROC oRtlVirtualUnwind;
	FARPROC oRtlZeroMemory;
	FARPROC oScrollConsoleScreenBufferA;
	FARPROC oScrollConsoleScreenBufferW;
	FARPROC oSearchPathA;
	FARPROC oSearchPathW;
	FARPROC oSetCachedSigningLevel;
	FARPROC oSetCalendarInfoA;
	FARPROC oSetCalendarInfoW;
	FARPROC oSetComPlusPackageInstallStatus;
	FARPROC oSetCommBreak;
	FARPROC oSetCommConfig;
	FARPROC oSetCommMask;
	FARPROC oSetCommState;
	FARPROC oSetCommTimeouts;
	FARPROC oSetComputerNameA;
	FARPROC oSetComputerNameEx2W;
	FARPROC oSetComputerNameExA;
	FARPROC oSetComputerNameExW;
	FARPROC oSetComputerNameW;
	FARPROC oSetConsoleActiveScreenBuffer;
	FARPROC oSetConsoleCP;
	FARPROC oSetConsoleCtrlHandler;
	FARPROC oSetConsoleCursor;
	FARPROC oSetConsoleCursorInfo;
	FARPROC oSetConsoleCursorMode;
	FARPROC oSetConsoleCursorPosition;
	FARPROC oSetConsoleDisplayMode;
	FARPROC oSetConsoleFont;
	FARPROC oSetConsoleHardwareState;
	FARPROC oSetConsoleHistoryInfo;
	FARPROC oSetConsoleIcon;
	FARPROC oSetConsoleInputExeNameA;
	FARPROC oSetConsoleInputExeNameW;
	FARPROC oSetConsoleKeyShortcuts;
	FARPROC oSetConsoleLocalEUDC;
	FARPROC oSetConsoleMaximumWindowSize;
	FARPROC oSetConsoleMenuClose;
	FARPROC oSetConsoleMode;
	FARPROC oSetConsoleNlsMode;
	FARPROC oSetConsoleNumberOfCommandsA;
	FARPROC oSetConsoleNumberOfCommandsW;
	FARPROC oSetConsoleOS2OemFormat;
	FARPROC oSetConsoleOutputCP;
	FARPROC oSetConsolePalette;
	FARPROC oSetConsoleScreenBufferInfoEx;
	FARPROC oSetConsoleScreenBufferSize;
	FARPROC oSetConsoleTextAttribute;
	FARPROC oSetConsoleTitleA;
	FARPROC oSetConsoleTitleW;
	FARPROC oSetConsoleWindowInfo;
	FARPROC oSetCriticalSectionSpinCount;
	FARPROC oSetCurrentConsoleFontEx;
	FARPROC oSetCurrentDirectoryA;
	FARPROC oSetCurrentDirectoryW;
	FARPROC oSetDefaultCommConfigA;
	FARPROC oSetDefaultCommConfigW;
	FARPROC oSetDefaultDllDirectories;
	FARPROC oSetDllDirectoryA;
	FARPROC oSetDllDirectoryW;
	FARPROC oSetDynamicTimeZoneInformation;
	FARPROC oSetEndOfFile;
	FARPROC oSetEnvironmentStringsA;
	FARPROC oSetEnvironmentStringsW;
	FARPROC oSetEnvironmentVariableA;
	FARPROC oSetEnvironmentVariableW;
	FARPROC oSetErrorMode;
	FARPROC oSetEvent;
	FARPROC oSetEventWhenCallbackReturns;
	FARPROC oSetFileApisToANSI;
	FARPROC oSetFileApisToOEM;
	FARPROC oSetFileAttributesA;
	FARPROC oSetFileAttributesTransactedA;
	FARPROC oSetFileAttributesTransactedW;
	FARPROC oSetFileAttributesW;
	FARPROC oSetFileBandwidthReservation;
	FARPROC oSetFileCompletionNotificationModes;
	FARPROC oSetFileInformationByHandle;
	FARPROC oSetFileIoOverlappedRange;
	FARPROC oSetFilePointer;
	FARPROC oSetFilePointerEx;
	FARPROC oSetFileShortNameA;
	FARPROC oSetFileShortNameW;
	FARPROC oSetFileTime;
	FARPROC oSetFileValidData;
	FARPROC oSetFirmwareEnvironmentVariableA;
	FARPROC oSetFirmwareEnvironmentVariableExA;
	FARPROC oSetFirmwareEnvironmentVariableExW;
	FARPROC oSetFirmwareEnvironmentVariableW;
	FARPROC oSetHandleCount;
	FARPROC oSetHandleInformation;
	FARPROC oSetInformationJobObject;
	FARPROC oSetIoRateControlInformationJobObject;
	FARPROC oSetLastConsoleEventActive;
	FARPROC oSetLastError;
	FARPROC oSetLocalPrimaryComputerNameA;
	FARPROC oSetLocalPrimaryComputerNameW;
	FARPROC oSetLocalTime;
	FARPROC oSetLocaleInfoA;
	FARPROC oSetLocaleInfoW;
	FARPROC oSetMailslotInfo;
	FARPROC oSetMessageWaitingIndicator;
	FARPROC oSetNamedPipeAttribute;
	FARPROC oSetNamedPipeHandleState;
	FARPROC oSetPriorityClass;
	FARPROC oSetProcessAffinityMask;
	FARPROC oSetProcessAffinityUpdateMode;
	FARPROC oSetProcessDEPPolicy;
	FARPROC oSetProcessDefaultCpuSets;
	FARPROC oSetProcessInformation;
	FARPROC oSetProcessMitigationPolicy;
	FARPROC oSetProcessPreferredUILanguages;
	FARPROC oSetProcessPriorityBoost;
	FARPROC oSetProcessShutdownParameters;
	FARPROC oSetProcessWorkingSetSize;
	FARPROC oSetProcessWorkingSetSizeEx;
	FARPROC oSetProtectedPolicy;
	FARPROC oSetSearchPathMode;
	FARPROC oSetStdHandle;
	FARPROC oSetStdHandleEx;
	FARPROC oSetSystemFileCacheSize;
	FARPROC oSetSystemPowerState;
	FARPROC oSetSystemTime;
	FARPROC oSetSystemTimeAdjustment;
	FARPROC oSetTapeParameters;
	FARPROC oSetTapePosition;
	FARPROC oSetTermsrvAppInstallMode;
	FARPROC oSetThreadAffinityMask;
	FARPROC oSetThreadContext;
	FARPROC oSetThreadDescription;
	FARPROC oSetThreadErrorMode;
	FARPROC oSetThreadExecutionState;
	FARPROC oSetThreadGroupAffinity;
	FARPROC oSetThreadIdealProcessor;
	FARPROC oSetThreadIdealProcessorEx;
	FARPROC oSetThreadInformation;
	FARPROC oSetThreadLocale;
	FARPROC oSetThreadPreferredUILanguages;
	FARPROC oSetThreadPriority;
	FARPROC oSetThreadPriorityBoost;
	FARPROC oSetThreadSelectedCpuSets;
	FARPROC oSetThreadStackGuarantee;
	FARPROC oSetThreadToken;
	FARPROC oSetThreadUILanguage;
	FARPROC oSetThreadpoolStackInformation;
	FARPROC oSetThreadpoolThreadMaximum;
	FARPROC oSetThreadpoolThreadMinimum;
	FARPROC oSetThreadpoolTimer;
	FARPROC oSetThreadpoolTimerEx;
	FARPROC oSetThreadpoolWait;
	FARPROC oSetThreadpoolWaitEx;
	FARPROC oSetTimeZoneInformation;
	FARPROC oSetTimerQueueTimer;
	FARPROC oSetUmsThreadInformation;
	FARPROC oSetUnhandledExceptionFilter;
	FARPROC oSetUserGeoID;
	FARPROC oSetUserGeoName;
	FARPROC oSetVDMCurrentDirectories;
	FARPROC oSetVolumeLabelA;
	FARPROC oSetVolumeLabelW;
	FARPROC oSetVolumeMountPointA;
	FARPROC oSetVolumeMountPointW;
	FARPROC oSetVolumeMountPointWStub;
	FARPROC oSetWaitableTimer;
	FARPROC oSetWaitableTimerEx;
	FARPROC oSetXStateFeaturesMask;
	FARPROC oSetupComm;
	FARPROC oShowConsoleCursor;
	FARPROC oSignalObjectAndWait;
	FARPROC oSizeofResource;
	FARPROC oSleep;
	FARPROC oSleepConditionVariableCS;
	FARPROC oSleepConditionVariableSRW;
	FARPROC oSleepEx;
	FARPROC oSortCloseHandle;
	FARPROC oSortGetHandle;
	FARPROC oStartThreadpoolIo;
	FARPROC oSubmitThreadpoolWork;
	FARPROC oSuspendThread;
	FARPROC oSwitchToFiber;
	FARPROC oSwitchToThread;
	FARPROC oSystemTimeToFileTime;
	FARPROC oSystemTimeToTzSpecificLocalTime;
	FARPROC oSystemTimeToTzSpecificLocalTimeEx;
	FARPROC oTerminateJobObject;
	FARPROC oTerminateProcess;
	FARPROC oTerminateThread;
	FARPROC oTermsrvAppInstallMode;
	FARPROC oTermsrvConvertSysRootToUserDir;
	FARPROC oTermsrvCreateRegEntry;
	FARPROC oTermsrvDeleteKey;
	FARPROC oTermsrvDeleteValue;
	FARPROC oTermsrvGetPreSetValue;
	FARPROC oTermsrvGetWindowsDirectoryA;
	FARPROC oTermsrvGetWindowsDirectoryW;
	FARPROC oTermsrvOpenRegEntry;
	FARPROC oTermsrvOpenUserClasses;
	FARPROC oTermsrvRestoreKey;
	FARPROC oTermsrvSetKeySecurity;
	FARPROC oTermsrvSetValueKey;
	FARPROC oTermsrvSyncUserIniFileExt;
	FARPROC oThread32First;
	FARPROC oThread32Next;
	FARPROC oTlsAlloc;
	FARPROC oTlsFree;
	FARPROC oTlsGetValue;
	FARPROC oTlsSetValue;
	FARPROC oToolhelp32ReadProcessMemory;
	FARPROC oTransactNamedPipe;
	FARPROC oTransmitCommChar;
	FARPROC oTryAcquireSRWLockExclusive;
	FARPROC oTryAcquireSRWLockShared;
	FARPROC oTryEnterCriticalSection;
	FARPROC oTrySubmitThreadpoolCallback;
	FARPROC oTzSpecificLocalTimeToSystemTime;
	FARPROC oTzSpecificLocalTimeToSystemTimeEx;
	FARPROC oUTRegister;
	FARPROC oUTUnRegister;
	FARPROC oUmsThreadYield;
	FARPROC oUnhandledExceptionFilter;
	FARPROC oUnlockFile;
	FARPROC oUnlockFileEx;
	FARPROC oUnmapViewOfFile;
	FARPROC oUnmapViewOfFileEx;
	FARPROC oUnregisterApplicationRecoveryCallback;
	FARPROC oUnregisterApplicationRestart;
	FARPROC oUnregisterBadMemoryNotification;
	FARPROC oUnregisterConsoleIME;
	FARPROC oUnregisterWait;
	FARPROC oUnregisterWaitEx;
	FARPROC oUnregisterWaitUntilOOBECompleted;
	FARPROC oUpdateCalendarDayOfWeek;
	FARPROC oUpdateProcThreadAttribute;
	FARPROC oUpdateResourceA;
	FARPROC oUpdateResourceW;
	FARPROC oVDMConsoleOperation;
	FARPROC oVDMOperationStarted;
	FARPROC oVerLanguageNameA;
	FARPROC oVerLanguageNameW;
	FARPROC oVerSetConditionMask;
	FARPROC oVerifyConsoleIoHandle;
	FARPROC oVerifyScripts;
	FARPROC oVerifyVersionInfoA;
	FARPROC oVerifyVersionInfoW;
	FARPROC oVirtualAlloc;
	FARPROC oVirtualAllocEx;
	FARPROC oVirtualAllocExNuma;
	FARPROC oVirtualFree;
	FARPROC oVirtualFreeEx;
	FARPROC oVirtualLock;
	FARPROC oVirtualProtect;
	FARPROC oVirtualProtectEx;
	FARPROC oVirtualQuery;
	FARPROC oVirtualQueryEx;
	FARPROC oVirtualUnlock;
	FARPROC oWTSGetActiveConsoleSessionId;
	FARPROC oWaitCommEvent;
	FARPROC oWaitForDebugEvent;
	FARPROC oWaitForDebugEventEx;
	FARPROC oWaitForMultipleObjects;
	FARPROC oWaitForMultipleObjectsEx;
	FARPROC oWaitForSingleObject;
	FARPROC oWaitForSingleObjectEx;
	FARPROC oWaitForThreadpoolIoCallbacks;
	FARPROC oWaitForThreadpoolTimerCallbacks;
	FARPROC oWaitForThreadpoolWaitCallbacks;
	FARPROC oWaitForThreadpoolWorkCallbacks;
	FARPROC oWaitNamedPipeA;
	FARPROC oWaitNamedPipeW;
	FARPROC oWakeAllConditionVariable;
	FARPROC oWakeConditionVariable;
	FARPROC oWerGetFlags;
	FARPROC oWerGetFlagsWorker;
	FARPROC oWerRegisterAdditionalProcess;
	FARPROC oWerRegisterAppLocalDump;
	FARPROC oWerRegisterCustomMetadata;
	FARPROC oWerRegisterExcludedMemoryBlock;
	FARPROC oWerRegisterFile;
	FARPROC oWerRegisterFileWorker;
	FARPROC oWerRegisterMemoryBlock;
	FARPROC oWerRegisterMemoryBlockWorker;
	FARPROC oWerRegisterRuntimeExceptionModule;
	FARPROC oWerRegisterRuntimeExceptionModuleWorker;
	FARPROC oWerSetFlags;
	FARPROC oWerSetFlagsWorker;
	FARPROC oWerUnregisterAdditionalProcess;
	FARPROC oWerUnregisterAppLocalDump;
	FARPROC oWerUnregisterCustomMetadata;
	FARPROC oWerUnregisterExcludedMemoryBlock;
	FARPROC oWerUnregisterFile;
	FARPROC oWerUnregisterFileWorker;
	FARPROC oWerUnregisterMemoryBlock;
	FARPROC oWerUnregisterMemoryBlockWorker;
	FARPROC oWerUnregisterRuntimeExceptionModule;
	FARPROC oWerUnregisterRuntimeExceptionModuleWorker;
	FARPROC oWerpGetDebugger;
	FARPROC oWerpInitiateRemoteRecovery;
	FARPROC oWerpLaunchAeDebug;
	FARPROC oWerpNotifyLoadStringResourceWorker;
	FARPROC oWerpNotifyUseStringResourceWorker;
	FARPROC oWideCharToMultiByte;
	FARPROC oWinExec;
	FARPROC oWow64DisableWow64FsRedirection;
	FARPROC oWow64EnableWow64FsRedirection;
	FARPROC oWow64GetThreadContext;
	FARPROC oWow64GetThreadSelectorEntry;
	FARPROC oWow64RevertWow64FsRedirection;
	FARPROC oWow64SetThreadContext;
	FARPROC oWow64SuspendThread;
	FARPROC oWriteConsoleA;
	FARPROC oWriteConsoleInputA;
	FARPROC oWriteConsoleInputVDMA;
	FARPROC oWriteConsoleInputVDMW;
	FARPROC oWriteConsoleInputW;
	FARPROC oWriteConsoleOutputA;
	FARPROC oWriteConsoleOutputAttribute;
	FARPROC oWriteConsoleOutputCharacterA;
	FARPROC oWriteConsoleOutputCharacterW;
	FARPROC oWriteConsoleOutputW;
	FARPROC oWriteConsoleW;
	FARPROC oWriteFile;
	FARPROC oWriteFileEx;
	FARPROC oWriteFileGather;
	FARPROC oWritePrivateProfileSectionA;
	FARPROC oWritePrivateProfileSectionW;
	FARPROC oWritePrivateProfileStringA;
	FARPROC oWritePrivateProfileStringW;
	FARPROC oWritePrivateProfileStructA;
	FARPROC oWritePrivateProfileStructW;
	FARPROC oWriteProcessMemory;
	FARPROC oWriteProfileSectionA;
	FARPROC oWriteProfileSectionW;
	FARPROC oWriteProfileStringA;
	FARPROC oWriteProfileStringW;
	FARPROC oWriteTapemark;
	FARPROC oZombifyActCtx;
	FARPROC oZombifyActCtxWorker;
	FARPROC o__C_specific_handler;
	FARPROC o__chkstk;
	FARPROC o__misaligned_access;
	FARPROC o_hread;
	FARPROC o_hwrite;
	FARPROC o_lclose;
	FARPROC o_lcreat;
	FARPROC o_llseek;
	FARPROC o_local_unwind;
	FARPROC o_lopen;
	FARPROC o_lread;
	FARPROC o_lwrite;
	FARPROC olstrcat;
	FARPROC olstrcatA;
	FARPROC olstrcatW;
	FARPROC olstrcmp;
	FARPROC olstrcmpA;
	FARPROC olstrcmpW;
	FARPROC olstrcmpi;
	FARPROC olstrcmpiA;
	FARPROC olstrcmpiW;
	FARPROC olstrcpy;
	FARPROC olstrcpyA;
	FARPROC olstrcpyW;
	FARPROC olstrcpyn;
	FARPROC olstrcpynA;
	FARPROC olstrcpynW;
	FARPROC olstrlen;
	FARPROC olstrlenA;
	FARPROC olstrlenW;
	FARPROC otimeBeginPeriod;
	FARPROC otimeEndPeriod;
	FARPROC otimeGetDevCaps;
	FARPROC otimeGetSystemTime;
	FARPROC otimeGetTime;
	FARPROC ouaw_lstrcmpW;
	FARPROC ouaw_lstrcmpiW;
	FARPROC ouaw_lstrlenW;
	FARPROC ouaw_wcschr;
	FARPROC ouaw_wcscpy;
	FARPROC ouaw_wcsicmp;
	FARPROC ouaw_wcslen;
	FARPROC ouaw_wcsrchr;
} kernel32;

extern "C" {
	FARPROC PA = 0;
	int runASM();

	void fAcquireSRWLockExclusive() { PA = kernel32.oAcquireSRWLockExclusive; runASM(); }
	void fAcquireSRWLockShared() { PA = kernel32.oAcquireSRWLockShared; runASM(); }
	void fActivateActCtx() { PA = kernel32.oActivateActCtx; runASM(); }
	void fActivateActCtxWorker() { PA = kernel32.oActivateActCtxWorker; runASM(); }
	void fAddAtomA() { PA = kernel32.oAddAtomA; runASM(); }
	void fAddAtomW() { PA = kernel32.oAddAtomW; runASM(); }
	void fAddConsoleAliasA() { PA = kernel32.oAddConsoleAliasA; runASM(); }
	void fAddConsoleAliasW() { PA = kernel32.oAddConsoleAliasW; runASM(); }
	void fAddDllDirectory() { PA = kernel32.oAddDllDirectory; runASM(); }
	void fAddIntegrityLabelToBoundaryDescriptor() { PA = kernel32.oAddIntegrityLabelToBoundaryDescriptor; runASM(); }
	void fAddLocalAlternateComputerNameA() { PA = kernel32.oAddLocalAlternateComputerNameA; runASM(); }
	void fAddLocalAlternateComputerNameW() { PA = kernel32.oAddLocalAlternateComputerNameW; runASM(); }
	void fAddRefActCtx() { PA = kernel32.oAddRefActCtx; runASM(); }
	void fAddRefActCtxWorker() { PA = kernel32.oAddRefActCtxWorker; runASM(); }
	void fAddResourceAttributeAce() { PA = kernel32.oAddResourceAttributeAce; runASM(); }
	void fAddSIDToBoundaryDescriptor() { PA = kernel32.oAddSIDToBoundaryDescriptor; runASM(); }
	void fAddScopedPolicyIDAce() { PA = kernel32.oAddScopedPolicyIDAce; runASM(); }
	void fAddSecureMemoryCacheCallback() { PA = kernel32.oAddSecureMemoryCacheCallback; runASM(); }
	void fAddVectoredContinueHandler() { PA = kernel32.oAddVectoredContinueHandler; runASM(); }
	void fAddVectoredExceptionHandler() { PA = kernel32.oAddVectoredExceptionHandler; runASM(); }
	void fAdjustCalendarDate() { PA = kernel32.oAdjustCalendarDate; runASM(); }
	void fAllocConsole() { PA = kernel32.oAllocConsole; runASM(); }
	void fAllocateUserPhysicalPages() { PA = kernel32.oAllocateUserPhysicalPages; runASM(); }
	void fAllocateUserPhysicalPagesNuma() { PA = kernel32.oAllocateUserPhysicalPagesNuma; runASM(); }
	void fAppPolicyGetClrCompat() { PA = kernel32.oAppPolicyGetClrCompat; runASM(); }
	void fAppPolicyGetCreateFileAccess() { PA = kernel32.oAppPolicyGetCreateFileAccess; runASM(); }
	void fAppPolicyGetLifecycleManagement() { PA = kernel32.oAppPolicyGetLifecycleManagement; runASM(); }
	void fAppPolicyGetMediaFoundationCodecLoading() { PA = kernel32.oAppPolicyGetMediaFoundationCodecLoading; runASM(); }
	void fAppPolicyGetProcessTerminationMethod() { PA = kernel32.oAppPolicyGetProcessTerminationMethod; runASM(); }
	void fAppPolicyGetShowDeveloperDiagnostic() { PA = kernel32.oAppPolicyGetShowDeveloperDiagnostic; runASM(); }
	void fAppPolicyGetThreadInitializationType() { PA = kernel32.oAppPolicyGetThreadInitializationType; runASM(); }
	void fAppPolicyGetWindowingModel() { PA = kernel32.oAppPolicyGetWindowingModel; runASM(); }
	void fAppXGetOSMaxVersionTested() { PA = kernel32.oAppXGetOSMaxVersionTested; runASM(); }
	void fApplicationRecoveryFinished() { PA = kernel32.oApplicationRecoveryFinished; runASM(); }
	void fApplicationRecoveryInProgress() { PA = kernel32.oApplicationRecoveryInProgress; runASM(); }
	void fAreFileApisANSI() { PA = kernel32.oAreFileApisANSI; runASM(); }
	void fAssignProcessToJobObject() { PA = kernel32.oAssignProcessToJobObject; runASM(); }
	void fAttachConsole() { PA = kernel32.oAttachConsole; runASM(); }
	void fBackupRead() { PA = kernel32.oBackupRead; runASM(); }
	void fBackupSeek() { PA = kernel32.oBackupSeek; runASM(); }
	void fBackupWrite() { PA = kernel32.oBackupWrite; runASM(); }
	void fBaseCheckAppcompatCache() { PA = kernel32.oBaseCheckAppcompatCache; runASM(); }
	void fBaseCheckAppcompatCacheEx() { PA = kernel32.oBaseCheckAppcompatCacheEx; runASM(); }
	void fBaseCheckAppcompatCacheExWorker() { PA = kernel32.oBaseCheckAppcompatCacheExWorker; runASM(); }
	void fBaseCheckAppcompatCacheWorker() { PA = kernel32.oBaseCheckAppcompatCacheWorker; runASM(); }
	void fBaseCheckElevation() { PA = kernel32.oBaseCheckElevation; runASM(); }
	void fBaseCleanupAppcompatCacheSupport() { PA = kernel32.oBaseCleanupAppcompatCacheSupport; runASM(); }
	void fBaseCleanupAppcompatCacheSupportWorker() { PA = kernel32.oBaseCleanupAppcompatCacheSupportWorker; runASM(); }
	void fBaseDestroyVDMEnvironment() { PA = kernel32.oBaseDestroyVDMEnvironment; runASM(); }
	void fBaseDllReadWriteIniFile() { PA = kernel32.oBaseDllReadWriteIniFile; runASM(); }
	void fBaseDumpAppcompatCache() { PA = kernel32.oBaseDumpAppcompatCache; runASM(); }
	void fBaseDumpAppcompatCacheWorker() { PA = kernel32.oBaseDumpAppcompatCacheWorker; runASM(); }
	void fBaseElevationPostProcessing() { PA = kernel32.oBaseElevationPostProcessing; runASM(); }
	void fBaseFlushAppcompatCache() { PA = kernel32.oBaseFlushAppcompatCache; runASM(); }
	void fBaseFlushAppcompatCacheWorker() { PA = kernel32.oBaseFlushAppcompatCacheWorker; runASM(); }
	void fBaseFormatObjectAttributes() { PA = kernel32.oBaseFormatObjectAttributes; runASM(); }
	void fBaseFormatTimeOut() { PA = kernel32.oBaseFormatTimeOut; runASM(); }
	void fBaseFreeAppCompatDataForProcessWorker() { PA = kernel32.oBaseFreeAppCompatDataForProcessWorker; runASM(); }
	void fBaseGenerateAppCompatData() { PA = kernel32.oBaseGenerateAppCompatData; runASM(); }
	void fBaseGetNamedObjectDirectory() { PA = kernel32.oBaseGetNamedObjectDirectory; runASM(); }
	void fBaseInitAppcompatCacheSupport() { PA = kernel32.oBaseInitAppcompatCacheSupport; runASM(); }
	void fBaseInitAppcompatCacheSupportWorker() { PA = kernel32.oBaseInitAppcompatCacheSupportWorker; runASM(); }
	void fBaseIsAppcompatInfrastructureDisabled() { PA = kernel32.oBaseIsAppcompatInfrastructureDisabled; runASM(); }
	void fBaseIsAppcompatInfrastructureDisabledWorker() { PA = kernel32.oBaseIsAppcompatInfrastructureDisabledWorker; runASM(); }
	void fBaseIsDosApplication() { PA = kernel32.oBaseIsDosApplication; runASM(); }
	void fBaseQueryModuleData() { PA = kernel32.oBaseQueryModuleData; runASM(); }
	void fBaseReadAppCompatDataForProcessWorker() { PA = kernel32.oBaseReadAppCompatDataForProcessWorker; runASM(); }
	void fBaseSetLastNTError() { PA = kernel32.oBaseSetLastNTError; runASM(); }
	void fBaseThreadInitThunk() { PA = kernel32.oBaseThreadInitThunk; runASM(); }
	void fBaseUpdateAppcompatCache() { PA = kernel32.oBaseUpdateAppcompatCache; runASM(); }
	void fBaseUpdateAppcompatCacheWorker() { PA = kernel32.oBaseUpdateAppcompatCacheWorker; runASM(); }
	void fBaseUpdateVDMEntry() { PA = kernel32.oBaseUpdateVDMEntry; runASM(); }
	void fBaseVerifyUnicodeString() { PA = kernel32.oBaseVerifyUnicodeString; runASM(); }
	void fBaseWriteErrorElevationRequiredEvent() { PA = kernel32.oBaseWriteErrorElevationRequiredEvent; runASM(); }
	void fBasep8BitStringToDynamicUnicodeString() { PA = kernel32.oBasep8BitStringToDynamicUnicodeString; runASM(); }
	void fBasepAllocateActivationContextActivationBlock() { PA = kernel32.oBasepAllocateActivationContextActivationBlock; runASM(); }
	void fBasepAnsiStringToDynamicUnicodeString() { PA = kernel32.oBasepAnsiStringToDynamicUnicodeString; runASM(); }
	void fBasepAppContainerEnvironmentExtension() { PA = kernel32.oBasepAppContainerEnvironmentExtension; runASM(); }
	void fBasepAppXExtension() { PA = kernel32.oBasepAppXExtension; runASM(); }
	void fBasepCheckAppCompat() { PA = kernel32.oBasepCheckAppCompat; runASM(); }
	void fBasepCheckWebBladeHashes() { PA = kernel32.oBasepCheckWebBladeHashes; runASM(); }
	void fBasepCheckWinSaferRestrictions() { PA = kernel32.oBasepCheckWinSaferRestrictions; runASM(); }
	void fBasepConstructSxsCreateProcessMessage() { PA = kernel32.oBasepConstructSxsCreateProcessMessage; runASM(); }
	void fBasepCopyEncryption() { PA = kernel32.oBasepCopyEncryption; runASM(); }
	void fBasepFreeActivationContextActivationBlock() { PA = kernel32.oBasepFreeActivationContextActivationBlock; runASM(); }
	void fBasepFreeAppCompatData() { PA = kernel32.oBasepFreeAppCompatData; runASM(); }
	void fBasepGetAppCompatData() { PA = kernel32.oBasepGetAppCompatData; runASM(); }
	void fBasepGetComputerNameFromNtPath() { PA = kernel32.oBasepGetComputerNameFromNtPath; runASM(); }
	void fBasepGetExeArchType() { PA = kernel32.oBasepGetExeArchType; runASM(); }
	void fBasepInitAppCompatData() { PA = kernel32.oBasepInitAppCompatData; runASM(); }
	void fBasepIsProcessAllowed() { PA = kernel32.oBasepIsProcessAllowed; runASM(); }
	void fBasepMapModuleHandle() { PA = kernel32.oBasepMapModuleHandle; runASM(); }
	void fBasepNotifyLoadStringResource() { PA = kernel32.oBasepNotifyLoadStringResource; runASM(); }
	void fBasepPostSuccessAppXExtension() { PA = kernel32.oBasepPostSuccessAppXExtension; runASM(); }
	void fBasepProcessInvalidImage() { PA = kernel32.oBasepProcessInvalidImage; runASM(); }
	void fBasepQueryAppCompat() { PA = kernel32.oBasepQueryAppCompat; runASM(); }
	void fBasepQueryModuleChpeSettings() { PA = kernel32.oBasepQueryModuleChpeSettings; runASM(); }
	void fBasepReleaseAppXContext() { PA = kernel32.oBasepReleaseAppXContext; runASM(); }
	void fBasepReleaseSxsCreateProcessUtilityStruct() { PA = kernel32.oBasepReleaseSxsCreateProcessUtilityStruct; runASM(); }
	void fBasepReportFault() { PA = kernel32.oBasepReportFault; runASM(); }
	void fBasepSetFileEncryptionCompression() { PA = kernel32.oBasepSetFileEncryptionCompression; runASM(); }
	void fBeep() { PA = kernel32.oBeep; runASM(); }
	void fBeginUpdateResourceA() { PA = kernel32.oBeginUpdateResourceA; runASM(); }
	void fBeginUpdateResourceW() { PA = kernel32.oBeginUpdateResourceW; runASM(); }
	void fBindIoCompletionCallback() { PA = kernel32.oBindIoCompletionCallback; runASM(); }
	void fBuildCommDCBA() { PA = kernel32.oBuildCommDCBA; runASM(); }
	void fBuildCommDCBAndTimeoutsA() { PA = kernel32.oBuildCommDCBAndTimeoutsA; runASM(); }
	void fBuildCommDCBAndTimeoutsW() { PA = kernel32.oBuildCommDCBAndTimeoutsW; runASM(); }
	void fBuildCommDCBW() { PA = kernel32.oBuildCommDCBW; runASM(); }
	void fCallNamedPipeA() { PA = kernel32.oCallNamedPipeA; runASM(); }
	void fCallNamedPipeW() { PA = kernel32.oCallNamedPipeW; runASM(); }
	void fCallbackMayRunLong() { PA = kernel32.oCallbackMayRunLong; runASM(); }
	void fCancelDeviceWakeupRequest() { PA = kernel32.oCancelDeviceWakeupRequest; runASM(); }
	void fCancelIo() { PA = kernel32.oCancelIo; runASM(); }
	void fCancelIoEx() { PA = kernel32.oCancelIoEx; runASM(); }
	void fCancelSynchronousIo() { PA = kernel32.oCancelSynchronousIo; runASM(); }
	void fCancelThreadpoolIo() { PA = kernel32.oCancelThreadpoolIo; runASM(); }
	void fCancelTimerQueueTimer() { PA = kernel32.oCancelTimerQueueTimer; runASM(); }
	void fCancelWaitableTimer() { PA = kernel32.oCancelWaitableTimer; runASM(); }
	void fCeipIsOptedIn() { PA = kernel32.oCeipIsOptedIn; runASM(); }
	void fChangeTimerQueueTimer() { PA = kernel32.oChangeTimerQueueTimer; runASM(); }
	void fCheckAllowDecryptedRemoteDestinationPolicy() { PA = kernel32.oCheckAllowDecryptedRemoteDestinationPolicy; runASM(); }
	void fCheckElevation() { PA = kernel32.oCheckElevation; runASM(); }
	void fCheckElevationEnabled() { PA = kernel32.oCheckElevationEnabled; runASM(); }
	void fCheckForReadOnlyResource() { PA = kernel32.oCheckForReadOnlyResource; runASM(); }
	void fCheckForReadOnlyResourceFilter() { PA = kernel32.oCheckForReadOnlyResourceFilter; runASM(); }
	void fCheckNameLegalDOS8Dot3A() { PA = kernel32.oCheckNameLegalDOS8Dot3A; runASM(); }
	void fCheckNameLegalDOS8Dot3W() { PA = kernel32.oCheckNameLegalDOS8Dot3W; runASM(); }
	void fCheckRemoteDebuggerPresent() { PA = kernel32.oCheckRemoteDebuggerPresent; runASM(); }
	void fCheckTokenCapability() { PA = kernel32.oCheckTokenCapability; runASM(); }
	void fCheckTokenMembershipEx() { PA = kernel32.oCheckTokenMembershipEx; runASM(); }
	void fClearCommBreak() { PA = kernel32.oClearCommBreak; runASM(); }
	void fClearCommError() { PA = kernel32.oClearCommError; runASM(); }
	void fCloseConsoleHandle() { PA = kernel32.oCloseConsoleHandle; runASM(); }
	void fCloseHandle() { PA = kernel32.oCloseHandle; runASM(); }
	void fClosePackageInfo() { PA = kernel32.oClosePackageInfo; runASM(); }
	void fClosePrivateNamespace() { PA = kernel32.oClosePrivateNamespace; runASM(); }
	void fCloseProfileUserMapping() { PA = kernel32.oCloseProfileUserMapping; runASM(); }
	void fClosePseudoConsole() { PA = kernel32.oClosePseudoConsole; runASM(); }
	void fCloseState() { PA = kernel32.oCloseState; runASM(); }
	void fCloseThreadpool() { PA = kernel32.oCloseThreadpool; runASM(); }
	void fCloseThreadpoolCleanupGroup() { PA = kernel32.oCloseThreadpoolCleanupGroup; runASM(); }
	void fCloseThreadpoolCleanupGroupMembers() { PA = kernel32.oCloseThreadpoolCleanupGroupMembers; runASM(); }
	void fCloseThreadpoolIo() { PA = kernel32.oCloseThreadpoolIo; runASM(); }
	void fCloseThreadpoolTimer() { PA = kernel32.oCloseThreadpoolTimer; runASM(); }
	void fCloseThreadpoolWait() { PA = kernel32.oCloseThreadpoolWait; runASM(); }
	void fCloseThreadpoolWork() { PA = kernel32.oCloseThreadpoolWork; runASM(); }
	void fCmdBatNotification() { PA = kernel32.oCmdBatNotification; runASM(); }
	void fCommConfigDialogA() { PA = kernel32.oCommConfigDialogA; runASM(); }
	void fCommConfigDialogW() { PA = kernel32.oCommConfigDialogW; runASM(); }
	void fCompareCalendarDates() { PA = kernel32.oCompareCalendarDates; runASM(); }
	void fCompareFileTime() { PA = kernel32.oCompareFileTime; runASM(); }
	void fCompareStringA() { PA = kernel32.oCompareStringA; runASM(); }
	void fCompareStringEx() { PA = kernel32.oCompareStringEx; runASM(); }
	void fCompareStringOrdinal() { PA = kernel32.oCompareStringOrdinal; runASM(); }
	void fCompareStringW() { PA = kernel32.oCompareStringW; runASM(); }
	void fConnectNamedPipe() { PA = kernel32.oConnectNamedPipe; runASM(); }
	void fConsoleMenuControl() { PA = kernel32.oConsoleMenuControl; runASM(); }
	void fContinueDebugEvent() { PA = kernel32.oContinueDebugEvent; runASM(); }
	void fConvertCalDateTimeToSystemTime() { PA = kernel32.oConvertCalDateTimeToSystemTime; runASM(); }
	void fConvertDefaultLocale() { PA = kernel32.oConvertDefaultLocale; runASM(); }
	void fConvertFiberToThread() { PA = kernel32.oConvertFiberToThread; runASM(); }
	void fConvertNLSDayOfWeekToWin32DayOfWeek() { PA = kernel32.oConvertNLSDayOfWeekToWin32DayOfWeek; runASM(); }
	void fConvertSystemTimeToCalDateTime() { PA = kernel32.oConvertSystemTimeToCalDateTime; runASM(); }
	void fConvertThreadToFiber() { PA = kernel32.oConvertThreadToFiber; runASM(); }
	void fConvertThreadToFiberEx() { PA = kernel32.oConvertThreadToFiberEx; runASM(); }
	void fCopyContext() { PA = kernel32.oCopyContext; runASM(); }
	void fCopyFile2() { PA = kernel32.oCopyFile2; runASM(); }
	void fCopyFileA() { PA = kernel32.oCopyFileA; runASM(); }
	void fCopyFileExA() { PA = kernel32.oCopyFileExA; runASM(); }
	void fCopyFileExW() { PA = kernel32.oCopyFileExW; runASM(); }
	void fCopyFileTransactedA() { PA = kernel32.oCopyFileTransactedA; runASM(); }
	void fCopyFileTransactedW() { PA = kernel32.oCopyFileTransactedW; runASM(); }
	void fCopyFileW() { PA = kernel32.oCopyFileW; runASM(); }
	void fCopyLZFile() { PA = kernel32.oCopyLZFile; runASM(); }
	void fCreateActCtxA() { PA = kernel32.oCreateActCtxA; runASM(); }
	void fCreateActCtxW() { PA = kernel32.oCreateActCtxW; runASM(); }
	void fCreateActCtxWWorker() { PA = kernel32.oCreateActCtxWWorker; runASM(); }
	void fCreateBoundaryDescriptorA() { PA = kernel32.oCreateBoundaryDescriptorA; runASM(); }
	void fCreateBoundaryDescriptorW() { PA = kernel32.oCreateBoundaryDescriptorW; runASM(); }
	void fCreateConsoleScreenBuffer() { PA = kernel32.oCreateConsoleScreenBuffer; runASM(); }
	void fCreateDirectoryA() { PA = kernel32.oCreateDirectoryA; runASM(); }
	void fCreateDirectoryExA() { PA = kernel32.oCreateDirectoryExA; runASM(); }
	void fCreateDirectoryExW() { PA = kernel32.oCreateDirectoryExW; runASM(); }
	void fCreateDirectoryTransactedA() { PA = kernel32.oCreateDirectoryTransactedA; runASM(); }
	void fCreateDirectoryTransactedW() { PA = kernel32.oCreateDirectoryTransactedW; runASM(); }
	void fCreateDirectoryW() { PA = kernel32.oCreateDirectoryW; runASM(); }
	void fCreateEnclave() { PA = kernel32.oCreateEnclave; runASM(); }
	void fCreateEventA() { PA = kernel32.oCreateEventA; runASM(); }
	void fCreateEventExA() { PA = kernel32.oCreateEventExA; runASM(); }
	void fCreateEventExW() { PA = kernel32.oCreateEventExW; runASM(); }
	void fCreateEventW() { PA = kernel32.oCreateEventW; runASM(); }
	void fCreateFiber() { PA = kernel32.oCreateFiber; runASM(); }
	void fCreateFiberEx() { PA = kernel32.oCreateFiberEx; runASM(); }
	void fCreateFile2() { PA = kernel32.oCreateFile2; runASM(); }
	void fCreateFileA() { PA = kernel32.oCreateFileA; runASM(); }
	void fCreateFileMappingA() { PA = kernel32.oCreateFileMappingA; runASM(); }
	void fCreateFileMappingFromApp() { PA = kernel32.oCreateFileMappingFromApp; runASM(); }
	void fCreateFileMappingNumaA() { PA = kernel32.oCreateFileMappingNumaA; runASM(); }
	void fCreateFileMappingNumaW() { PA = kernel32.oCreateFileMappingNumaW; runASM(); }
	void fCreateFileMappingW() { PA = kernel32.oCreateFileMappingW; runASM(); }
	void fCreateFileTransactedA() { PA = kernel32.oCreateFileTransactedA; runASM(); }
	void fCreateFileTransactedW() { PA = kernel32.oCreateFileTransactedW; runASM(); }
	void fCreateFileW() { PA = kernel32.oCreateFileW; runASM(); }
	void fCreateHardLinkA() { PA = kernel32.oCreateHardLinkA; runASM(); }
	void fCreateHardLinkTransactedA() { PA = kernel32.oCreateHardLinkTransactedA; runASM(); }
	void fCreateHardLinkTransactedW() { PA = kernel32.oCreateHardLinkTransactedW; runASM(); }
	void fCreateHardLinkW() { PA = kernel32.oCreateHardLinkW; runASM(); }
	void fCreateIoCompletionPort() { PA = kernel32.oCreateIoCompletionPort; runASM(); }
	void fCreateJobObjectA() { PA = kernel32.oCreateJobObjectA; runASM(); }
	void fCreateJobObjectW() { PA = kernel32.oCreateJobObjectW; runASM(); }
	void fCreateJobSet() { PA = kernel32.oCreateJobSet; runASM(); }
	void fCreateMailslotA() { PA = kernel32.oCreateMailslotA; runASM(); }
	void fCreateMailslotW() { PA = kernel32.oCreateMailslotW; runASM(); }
	void fCreateMemoryResourceNotification() { PA = kernel32.oCreateMemoryResourceNotification; runASM(); }
	void fCreateMutexA() { PA = kernel32.oCreateMutexA; runASM(); }
	void fCreateMutexExA() { PA = kernel32.oCreateMutexExA; runASM(); }
	void fCreateMutexExW() { PA = kernel32.oCreateMutexExW; runASM(); }
	void fCreateMutexW() { PA = kernel32.oCreateMutexW; runASM(); }
	void fCreateNamedPipeA() { PA = kernel32.oCreateNamedPipeA; runASM(); }
	void fCreateNamedPipeW() { PA = kernel32.oCreateNamedPipeW; runASM(); }
	void fCreatePipe() { PA = kernel32.oCreatePipe; runASM(); }
	void fCreatePrivateNamespaceA() { PA = kernel32.oCreatePrivateNamespaceA; runASM(); }
	void fCreatePrivateNamespaceW() { PA = kernel32.oCreatePrivateNamespaceW; runASM(); }
	void fCreateProcessA() { PA = kernel32.oCreateProcessA; runASM(); }
	void fCreateProcessAsUserA() { PA = kernel32.oCreateProcessAsUserA; runASM(); }
	void fCreateProcessAsUserW() { PA = kernel32.oCreateProcessAsUserW; runASM(); }
	void fCreateProcessInternalA() { PA = kernel32.oCreateProcessInternalA; runASM(); }
	void fCreateProcessInternalW() { PA = kernel32.oCreateProcessInternalW; runASM(); }
	void fCreateProcessW() { PA = kernel32.oCreateProcessW; runASM(); }
	void fCreatePseudoConsole() { PA = kernel32.oCreatePseudoConsole; runASM(); }
	void fCreateRemoteThread() { PA = kernel32.oCreateRemoteThread; runASM(); }
	void fCreateRemoteThreadEx() { PA = kernel32.oCreateRemoteThreadEx; runASM(); }
	void fCreateSemaphoreA() { PA = kernel32.oCreateSemaphoreA; runASM(); }
	void fCreateSemaphoreExA() { PA = kernel32.oCreateSemaphoreExA; runASM(); }
	void fCreateSemaphoreExW() { PA = kernel32.oCreateSemaphoreExW; runASM(); }
	void fCreateSemaphoreW() { PA = kernel32.oCreateSemaphoreW; runASM(); }
	void fCreateSymbolicLinkA() { PA = kernel32.oCreateSymbolicLinkA; runASM(); }
	void fCreateSymbolicLinkTransactedA() { PA = kernel32.oCreateSymbolicLinkTransactedA; runASM(); }
	void fCreateSymbolicLinkTransactedW() { PA = kernel32.oCreateSymbolicLinkTransactedW; runASM(); }
	void fCreateSymbolicLinkW() { PA = kernel32.oCreateSymbolicLinkW; runASM(); }
	void fCreateTapePartition() { PA = kernel32.oCreateTapePartition; runASM(); }
	void fCreateThread() { PA = kernel32.oCreateThread; runASM(); }
	void fCreateThreadpool() { PA = kernel32.oCreateThreadpool; runASM(); }
	void fCreateThreadpoolCleanupGroup() { PA = kernel32.oCreateThreadpoolCleanupGroup; runASM(); }
	void fCreateThreadpoolIo() { PA = kernel32.oCreateThreadpoolIo; runASM(); }
	void fCreateThreadpoolTimer() { PA = kernel32.oCreateThreadpoolTimer; runASM(); }
	void fCreateThreadpoolWait() { PA = kernel32.oCreateThreadpoolWait; runASM(); }
	void fCreateThreadpoolWork() { PA = kernel32.oCreateThreadpoolWork; runASM(); }
	void fCreateTimerQueue() { PA = kernel32.oCreateTimerQueue; runASM(); }
	void fCreateTimerQueueTimer() { PA = kernel32.oCreateTimerQueueTimer; runASM(); }
	void fCreateToolhelp32Snapshot() { PA = kernel32.oCreateToolhelp32Snapshot; runASM(); }
	void fCreateUmsCompletionList() { PA = kernel32.oCreateUmsCompletionList; runASM(); }
	void fCreateUmsThreadContext() { PA = kernel32.oCreateUmsThreadContext; runASM(); }
	void fCreateWaitableTimerA() { PA = kernel32.oCreateWaitableTimerA; runASM(); }
	void fCreateWaitableTimerExA() { PA = kernel32.oCreateWaitableTimerExA; runASM(); }
	void fCreateWaitableTimerExW() { PA = kernel32.oCreateWaitableTimerExW; runASM(); }
	void fCreateWaitableTimerW() { PA = kernel32.oCreateWaitableTimerW; runASM(); }
	void fCtrlRoutine() { PA = kernel32.oCtrlRoutine; runASM(); }
	void fDeactivateActCtx() { PA = kernel32.oDeactivateActCtx; runASM(); }
	void fDeactivateActCtxWorker() { PA = kernel32.oDeactivateActCtxWorker; runASM(); }
	void fDebugActiveProcess() { PA = kernel32.oDebugActiveProcess; runASM(); }
	void fDebugActiveProcessStop() { PA = kernel32.oDebugActiveProcessStop; runASM(); }
	void fDebugBreak() { PA = kernel32.oDebugBreak; runASM(); }
	void fDebugBreakProcess() { PA = kernel32.oDebugBreakProcess; runASM(); }
	void fDebugSetProcessKillOnExit() { PA = kernel32.oDebugSetProcessKillOnExit; runASM(); }
	void fDecodePointer() { PA = kernel32.oDecodePointer; runASM(); }
	void fDecodeSystemPointer() { PA = kernel32.oDecodeSystemPointer; runASM(); }
	void fDefineDosDeviceA() { PA = kernel32.oDefineDosDeviceA; runASM(); }
	void fDefineDosDeviceW() { PA = kernel32.oDefineDosDeviceW; runASM(); }
	void fDelayLoadFailureHook() { PA = kernel32.oDelayLoadFailureHook; runASM(); }
	void fDeleteAtom() { PA = kernel32.oDeleteAtom; runASM(); }
	void fDeleteBoundaryDescriptor() { PA = kernel32.oDeleteBoundaryDescriptor; runASM(); }
	void fDeleteCriticalSection() { PA = kernel32.oDeleteCriticalSection; runASM(); }
	void fDeleteFiber() { PA = kernel32.oDeleteFiber; runASM(); }
	void fDeleteFileA() { PA = kernel32.oDeleteFileA; runASM(); }
	void fDeleteFileTransactedA() { PA = kernel32.oDeleteFileTransactedA; runASM(); }
	void fDeleteFileTransactedW() { PA = kernel32.oDeleteFileTransactedW; runASM(); }
	void fDeleteFileW() { PA = kernel32.oDeleteFileW; runASM(); }
	void fDeleteProcThreadAttributeList() { PA = kernel32.oDeleteProcThreadAttributeList; runASM(); }
	void fDeleteSynchronizationBarrier() { PA = kernel32.oDeleteSynchronizationBarrier; runASM(); }
	void fDeleteTimerQueue() { PA = kernel32.oDeleteTimerQueue; runASM(); }
	void fDeleteTimerQueueEx() { PA = kernel32.oDeleteTimerQueueEx; runASM(); }
	void fDeleteTimerQueueTimer() { PA = kernel32.oDeleteTimerQueueTimer; runASM(); }
	void fDeleteUmsCompletionList() { PA = kernel32.oDeleteUmsCompletionList; runASM(); }
	void fDeleteUmsThreadContext() { PA = kernel32.oDeleteUmsThreadContext; runASM(); }
	void fDeleteVolumeMountPointA() { PA = kernel32.oDeleteVolumeMountPointA; runASM(); }
	void fDeleteVolumeMountPointW() { PA = kernel32.oDeleteVolumeMountPointW; runASM(); }
	void fDequeueUmsCompletionListItems() { PA = kernel32.oDequeueUmsCompletionListItems; runASM(); }
	void fDeviceIoControl() { PA = kernel32.oDeviceIoControl; runASM(); }
	void fDisableThreadLibraryCalls() { PA = kernel32.oDisableThreadLibraryCalls; runASM(); }
	void fDisableThreadProfiling() { PA = kernel32.oDisableThreadProfiling; runASM(); }
	void fDisassociateCurrentThreadFromCallback() { PA = kernel32.oDisassociateCurrentThreadFromCallback; runASM(); }
	void fDiscardVirtualMemory() { PA = kernel32.oDiscardVirtualMemory; runASM(); }
	void fDisconnectNamedPipe() { PA = kernel32.oDisconnectNamedPipe; runASM(); }
	void fDnsHostnameToComputerNameA() { PA = kernel32.oDnsHostnameToComputerNameA; runASM(); }
	void fDnsHostnameToComputerNameExW() { PA = kernel32.oDnsHostnameToComputerNameExW; runASM(); }
	void fDnsHostnameToComputerNameW() { PA = kernel32.oDnsHostnameToComputerNameW; runASM(); }
	void fDosDateTimeToFileTime() { PA = kernel32.oDosDateTimeToFileTime; runASM(); }
	void fDosPathToSessionPathA() { PA = kernel32.oDosPathToSessionPathA; runASM(); }
	void fDosPathToSessionPathW() { PA = kernel32.oDosPathToSessionPathW; runASM(); }
	void fDuplicateConsoleHandle() { PA = kernel32.oDuplicateConsoleHandle; runASM(); }
	void fDuplicateEncryptionInfoFileExt() { PA = kernel32.oDuplicateEncryptionInfoFileExt; runASM(); }
	void fDuplicateHandle() { PA = kernel32.oDuplicateHandle; runASM(); }
	void fEnableThreadProfiling() { PA = kernel32.oEnableThreadProfiling; runASM(); }
	void fEncodePointer() { PA = kernel32.oEncodePointer; runASM(); }
	void fEncodeSystemPointer() { PA = kernel32.oEncodeSystemPointer; runASM(); }
	void fEndUpdateResourceA() { PA = kernel32.oEndUpdateResourceA; runASM(); }
	void fEndUpdateResourceW() { PA = kernel32.oEndUpdateResourceW; runASM(); }
	void fEnterCriticalSection() { PA = kernel32.oEnterCriticalSection; runASM(); }
	void fEnterSynchronizationBarrier() { PA = kernel32.oEnterSynchronizationBarrier; runASM(); }
	void fEnterUmsSchedulingMode() { PA = kernel32.oEnterUmsSchedulingMode; runASM(); }
	void fEnumCalendarInfoA() { PA = kernel32.oEnumCalendarInfoA; runASM(); }
	void fEnumCalendarInfoExA() { PA = kernel32.oEnumCalendarInfoExA; runASM(); }
	void fEnumCalendarInfoExEx() { PA = kernel32.oEnumCalendarInfoExEx; runASM(); }
	void fEnumCalendarInfoExW() { PA = kernel32.oEnumCalendarInfoExW; runASM(); }
	void fEnumCalendarInfoW() { PA = kernel32.oEnumCalendarInfoW; runASM(); }
	void fEnumDateFormatsA() { PA = kernel32.oEnumDateFormatsA; runASM(); }
	void fEnumDateFormatsExA() { PA = kernel32.oEnumDateFormatsExA; runASM(); }
	void fEnumDateFormatsExEx() { PA = kernel32.oEnumDateFormatsExEx; runASM(); }
	void fEnumDateFormatsExW() { PA = kernel32.oEnumDateFormatsExW; runASM(); }
	void fEnumDateFormatsW() { PA = kernel32.oEnumDateFormatsW; runASM(); }
	void fEnumLanguageGroupLocalesA() { PA = kernel32.oEnumLanguageGroupLocalesA; runASM(); }
	void fEnumLanguageGroupLocalesW() { PA = kernel32.oEnumLanguageGroupLocalesW; runASM(); }
	void fEnumResourceLanguagesA() { PA = kernel32.oEnumResourceLanguagesA; runASM(); }
	void fEnumResourceLanguagesExA() { PA = kernel32.oEnumResourceLanguagesExA; runASM(); }
	void fEnumResourceLanguagesExW() { PA = kernel32.oEnumResourceLanguagesExW; runASM(); }
	void fEnumResourceLanguagesW() { PA = kernel32.oEnumResourceLanguagesW; runASM(); }
	void fEnumResourceNamesA() { PA = kernel32.oEnumResourceNamesA; runASM(); }
	void fEnumResourceNamesExA() { PA = kernel32.oEnumResourceNamesExA; runASM(); }
	void fEnumResourceNamesExW() { PA = kernel32.oEnumResourceNamesExW; runASM(); }
	void fEnumResourceNamesW() { PA = kernel32.oEnumResourceNamesW; runASM(); }
	void fEnumResourceTypesA() { PA = kernel32.oEnumResourceTypesA; runASM(); }
	void fEnumResourceTypesExA() { PA = kernel32.oEnumResourceTypesExA; runASM(); }
	void fEnumResourceTypesExW() { PA = kernel32.oEnumResourceTypesExW; runASM(); }
	void fEnumResourceTypesW() { PA = kernel32.oEnumResourceTypesW; runASM(); }
	void fEnumSystemCodePagesA() { PA = kernel32.oEnumSystemCodePagesA; runASM(); }
	void fEnumSystemCodePagesW() { PA = kernel32.oEnumSystemCodePagesW; runASM(); }
	void fEnumSystemFirmwareTables() { PA = kernel32.oEnumSystemFirmwareTables; runASM(); }
	void fEnumSystemGeoID() { PA = kernel32.oEnumSystemGeoID; runASM(); }
	void fEnumSystemGeoNames() { PA = kernel32.oEnumSystemGeoNames; runASM(); }
	void fEnumSystemLanguageGroupsA() { PA = kernel32.oEnumSystemLanguageGroupsA; runASM(); }
	void fEnumSystemLanguageGroupsW() { PA = kernel32.oEnumSystemLanguageGroupsW; runASM(); }
	void fEnumSystemLocalesA() { PA = kernel32.oEnumSystemLocalesA; runASM(); }
	void fEnumSystemLocalesEx() { PA = kernel32.oEnumSystemLocalesEx; runASM(); }
	void fEnumSystemLocalesW() { PA = kernel32.oEnumSystemLocalesW; runASM(); }
	void fEnumTimeFormatsA() { PA = kernel32.oEnumTimeFormatsA; runASM(); }
	void fEnumTimeFormatsEx() { PA = kernel32.oEnumTimeFormatsEx; runASM(); }
	void fEnumTimeFormatsW() { PA = kernel32.oEnumTimeFormatsW; runASM(); }
	void fEnumUILanguagesA() { PA = kernel32.oEnumUILanguagesA; runASM(); }
	void fEnumUILanguagesW() { PA = kernel32.oEnumUILanguagesW; runASM(); }
	void fEnumerateLocalComputerNamesA() { PA = kernel32.oEnumerateLocalComputerNamesA; runASM(); }
	void fEnumerateLocalComputerNamesW() { PA = kernel32.oEnumerateLocalComputerNamesW; runASM(); }
	void fEraseTape() { PA = kernel32.oEraseTape; runASM(); }
	void fEscapeCommFunction() { PA = kernel32.oEscapeCommFunction; runASM(); }
	void fExecuteUmsThread() { PA = kernel32.oExecuteUmsThread; runASM(); }
	void fExitProcess() { PA = kernel32.oExitProcess; runASM(); }
	void fExitThread() { PA = kernel32.oExitThread; runASM(); }
	void fExitVDM() { PA = kernel32.oExitVDM; runASM(); }
	void fExpandEnvironmentStringsA() { PA = kernel32.oExpandEnvironmentStringsA; runASM(); }
	void fExpandEnvironmentStringsW() { PA = kernel32.oExpandEnvironmentStringsW; runASM(); }
	void fExpungeConsoleCommandHistoryA() { PA = kernel32.oExpungeConsoleCommandHistoryA; runASM(); }
	void fExpungeConsoleCommandHistoryW() { PA = kernel32.oExpungeConsoleCommandHistoryW; runASM(); }
	void fFatalAppExitA() { PA = kernel32.oFatalAppExitA; runASM(); }
	void fFatalAppExitW() { PA = kernel32.oFatalAppExitW; runASM(); }
	void fFatalExit() { PA = kernel32.oFatalExit; runASM(); }
	void fFileTimeToDosDateTime() { PA = kernel32.oFileTimeToDosDateTime; runASM(); }
	void fFileTimeToLocalFileTime() { PA = kernel32.oFileTimeToLocalFileTime; runASM(); }
	void fFileTimeToSystemTime() { PA = kernel32.oFileTimeToSystemTime; runASM(); }
	void fFillConsoleOutputAttribute() { PA = kernel32.oFillConsoleOutputAttribute; runASM(); }
	void fFillConsoleOutputCharacterA() { PA = kernel32.oFillConsoleOutputCharacterA; runASM(); }
	void fFillConsoleOutputCharacterW() { PA = kernel32.oFillConsoleOutputCharacterW; runASM(); }
	void fFindActCtxSectionGuid() { PA = kernel32.oFindActCtxSectionGuid; runASM(); }
	void fFindActCtxSectionGuidWorker() { PA = kernel32.oFindActCtxSectionGuidWorker; runASM(); }
	void fFindActCtxSectionStringA() { PA = kernel32.oFindActCtxSectionStringA; runASM(); }
	void fFindActCtxSectionStringW() { PA = kernel32.oFindActCtxSectionStringW; runASM(); }
	void fFindActCtxSectionStringWWorker() { PA = kernel32.oFindActCtxSectionStringWWorker; runASM(); }
	void fFindAtomA() { PA = kernel32.oFindAtomA; runASM(); }
	void fFindAtomW() { PA = kernel32.oFindAtomW; runASM(); }
	void fFindClose() { PA = kernel32.oFindClose; runASM(); }
	void fFindCloseChangeNotification() { PA = kernel32.oFindCloseChangeNotification; runASM(); }
	void fFindFirstChangeNotificationA() { PA = kernel32.oFindFirstChangeNotificationA; runASM(); }
	void fFindFirstChangeNotificationW() { PA = kernel32.oFindFirstChangeNotificationW; runASM(); }
	void fFindFirstFileA() { PA = kernel32.oFindFirstFileA; runASM(); }
	void fFindFirstFileExA() { PA = kernel32.oFindFirstFileExA; runASM(); }
	void fFindFirstFileExW() { PA = kernel32.oFindFirstFileExW; runASM(); }
	void fFindFirstFileNameTransactedW() { PA = kernel32.oFindFirstFileNameTransactedW; runASM(); }
	void fFindFirstFileNameW() { PA = kernel32.oFindFirstFileNameW; runASM(); }
	void fFindFirstFileTransactedA() { PA = kernel32.oFindFirstFileTransactedA; runASM(); }
	void fFindFirstFileTransactedW() { PA = kernel32.oFindFirstFileTransactedW; runASM(); }
	void fFindFirstFileW() { PA = kernel32.oFindFirstFileW; runASM(); }
	void fFindFirstStreamTransactedW() { PA = kernel32.oFindFirstStreamTransactedW; runASM(); }
	void fFindFirstStreamW() { PA = kernel32.oFindFirstStreamW; runASM(); }
	void fFindFirstVolumeA() { PA = kernel32.oFindFirstVolumeA; runASM(); }
	void fFindFirstVolumeMountPointA() { PA = kernel32.oFindFirstVolumeMountPointA; runASM(); }
	void fFindFirstVolumeMountPointW() { PA = kernel32.oFindFirstVolumeMountPointW; runASM(); }
	void fFindFirstVolumeW() { PA = kernel32.oFindFirstVolumeW; runASM(); }
	void fFindNLSString() { PA = kernel32.oFindNLSString; runASM(); }
	void fFindNLSStringEx() { PA = kernel32.oFindNLSStringEx; runASM(); }
	void fFindNextChangeNotification() { PA = kernel32.oFindNextChangeNotification; runASM(); }
	void fFindNextFileA() { PA = kernel32.oFindNextFileA; runASM(); }
	void fFindNextFileNameW() { PA = kernel32.oFindNextFileNameW; runASM(); }
	void fFindNextFileW() { PA = kernel32.oFindNextFileW; runASM(); }
	void fFindNextStreamW() { PA = kernel32.oFindNextStreamW; runASM(); }
	void fFindNextVolumeA() { PA = kernel32.oFindNextVolumeA; runASM(); }
	void fFindNextVolumeMountPointA() { PA = kernel32.oFindNextVolumeMountPointA; runASM(); }
	void fFindNextVolumeMountPointW() { PA = kernel32.oFindNextVolumeMountPointW; runASM(); }
	void fFindNextVolumeW() { PA = kernel32.oFindNextVolumeW; runASM(); }
	void fFindPackagesByPackageFamily() { PA = kernel32.oFindPackagesByPackageFamily; runASM(); }
	void fFindResourceA() { PA = kernel32.oFindResourceA; runASM(); }
	void fFindResourceExA() { PA = kernel32.oFindResourceExA; runASM(); }
	void fFindResourceExW() { PA = kernel32.oFindResourceExW; runASM(); }
	void fFindResourceW() { PA = kernel32.oFindResourceW; runASM(); }
	void fFindStringOrdinal() { PA = kernel32.oFindStringOrdinal; runASM(); }
	void fFindVolumeClose() { PA = kernel32.oFindVolumeClose; runASM(); }
	void fFindVolumeMountPointClose() { PA = kernel32.oFindVolumeMountPointClose; runASM(); }
	void fFlsAlloc() { PA = kernel32.oFlsAlloc; runASM(); }
	void fFlsFree() { PA = kernel32.oFlsFree; runASM(); }
	void fFlsGetValue() { PA = kernel32.oFlsGetValue; runASM(); }
	void fFlsSetValue() { PA = kernel32.oFlsSetValue; runASM(); }
	void fFlushConsoleInputBuffer() { PA = kernel32.oFlushConsoleInputBuffer; runASM(); }
	void fFlushFileBuffers() { PA = kernel32.oFlushFileBuffers; runASM(); }
	void fFlushInstructionCache() { PA = kernel32.oFlushInstructionCache; runASM(); }
	void fFlushProcessWriteBuffers() { PA = kernel32.oFlushProcessWriteBuffers; runASM(); }
	void fFlushViewOfFile() { PA = kernel32.oFlushViewOfFile; runASM(); }
	void fFoldStringA() { PA = kernel32.oFoldStringA; runASM(); }
	void fFoldStringW() { PA = kernel32.oFoldStringW; runASM(); }
	void fFormatApplicationUserModelId() { PA = kernel32.oFormatApplicationUserModelId; runASM(); }
	void fFormatMessageA() { PA = kernel32.oFormatMessageA; runASM(); }
	void fFormatMessageW() { PA = kernel32.oFormatMessageW; runASM(); }
	void fFreeConsole() { PA = kernel32.oFreeConsole; runASM(); }
	void fFreeEnvironmentStringsA() { PA = kernel32.oFreeEnvironmentStringsA; runASM(); }
	void fFreeEnvironmentStringsW() { PA = kernel32.oFreeEnvironmentStringsW; runASM(); }
	void fFreeLibrary() { PA = kernel32.oFreeLibrary; runASM(); }
	void fFreeLibraryAndExitThread() { PA = kernel32.oFreeLibraryAndExitThread; runASM(); }
	void fFreeLibraryWhenCallbackReturns() { PA = kernel32.oFreeLibraryWhenCallbackReturns; runASM(); }
	void fFreeMemoryJobObject() { PA = kernel32.oFreeMemoryJobObject; runASM(); }
	void fFreeResource() { PA = kernel32.oFreeResource; runASM(); }
	void fFreeUserPhysicalPages() { PA = kernel32.oFreeUserPhysicalPages; runASM(); }
	void fGenerateConsoleCtrlEvent() { PA = kernel32.oGenerateConsoleCtrlEvent; runASM(); }
	void fGetACP() { PA = kernel32.oGetACP; runASM(); }
	void fGetActiveProcessorCount() { PA = kernel32.oGetActiveProcessorCount; runASM(); }
	void fGetActiveProcessorGroupCount() { PA = kernel32.oGetActiveProcessorGroupCount; runASM(); }
	void fGetAppContainerAce() { PA = kernel32.oGetAppContainerAce; runASM(); }
	void fGetAppContainerNamedObjectPath() { PA = kernel32.oGetAppContainerNamedObjectPath; runASM(); }
	void fGetApplicationRecoveryCallback() { PA = kernel32.oGetApplicationRecoveryCallback; runASM(); }
	void fGetApplicationRecoveryCallbackWorker() { PA = kernel32.oGetApplicationRecoveryCallbackWorker; runASM(); }
	void fGetApplicationRestartSettings() { PA = kernel32.oGetApplicationRestartSettings; runASM(); }
	void fGetApplicationRestartSettingsWorker() { PA = kernel32.oGetApplicationRestartSettingsWorker; runASM(); }
	void fGetApplicationUserModelId() { PA = kernel32.oGetApplicationUserModelId; runASM(); }
	void fGetAtomNameA() { PA = kernel32.oGetAtomNameA; runASM(); }
	void fGetAtomNameW() { PA = kernel32.oGetAtomNameW; runASM(); }
	void fGetBinaryType() { PA = kernel32.oGetBinaryType; runASM(); }
	void fGetBinaryTypeA() { PA = kernel32.oGetBinaryTypeA; runASM(); }
	void fGetBinaryTypeW() { PA = kernel32.oGetBinaryTypeW; runASM(); }
	void fGetCPInfo() { PA = kernel32.oGetCPInfo; runASM(); }
	void fGetCPInfoExA() { PA = kernel32.oGetCPInfoExA; runASM(); }
	void fGetCPInfoExW() { PA = kernel32.oGetCPInfoExW; runASM(); }
	void fGetCachedSigningLevel() { PA = kernel32.oGetCachedSigningLevel; runASM(); }
	void fGetCalendarDateFormat() { PA = kernel32.oGetCalendarDateFormat; runASM(); }
	void fGetCalendarDateFormatEx() { PA = kernel32.oGetCalendarDateFormatEx; runASM(); }
	void fGetCalendarDaysInMonth() { PA = kernel32.oGetCalendarDaysInMonth; runASM(); }
	void fGetCalendarDifferenceInDays() { PA = kernel32.oGetCalendarDifferenceInDays; runASM(); }
	void fGetCalendarInfoA() { PA = kernel32.oGetCalendarInfoA; runASM(); }
	void fGetCalendarInfoEx() { PA = kernel32.oGetCalendarInfoEx; runASM(); }
	void fGetCalendarInfoW() { PA = kernel32.oGetCalendarInfoW; runASM(); }
	void fGetCalendarMonthsInYear() { PA = kernel32.oGetCalendarMonthsInYear; runASM(); }
	void fGetCalendarSupportedDateRange() { PA = kernel32.oGetCalendarSupportedDateRange; runASM(); }
	void fGetCalendarWeekNumber() { PA = kernel32.oGetCalendarWeekNumber; runASM(); }
	void fGetComPlusPackageInstallStatus() { PA = kernel32.oGetComPlusPackageInstallStatus; runASM(); }
	void fGetCommConfig() { PA = kernel32.oGetCommConfig; runASM(); }
	void fGetCommMask() { PA = kernel32.oGetCommMask; runASM(); }
	void fGetCommModemStatus() { PA = kernel32.oGetCommModemStatus; runASM(); }
	void fGetCommProperties() { PA = kernel32.oGetCommProperties; runASM(); }
	void fGetCommState() { PA = kernel32.oGetCommState; runASM(); }
	void fGetCommTimeouts() { PA = kernel32.oGetCommTimeouts; runASM(); }
	void fGetCommandLineA() { PA = kernel32.oGetCommandLineA; runASM(); }
	void fGetCommandLineW() { PA = kernel32.oGetCommandLineW; runASM(); }
	void fGetCompressedFileSizeA() { PA = kernel32.oGetCompressedFileSizeA; runASM(); }
	void fGetCompressedFileSizeTransactedA() { PA = kernel32.oGetCompressedFileSizeTransactedA; runASM(); }
	void fGetCompressedFileSizeTransactedW() { PA = kernel32.oGetCompressedFileSizeTransactedW; runASM(); }
	void fGetCompressedFileSizeW() { PA = kernel32.oGetCompressedFileSizeW; runASM(); }
	void fGetComputerNameA() { PA = kernel32.oGetComputerNameA; runASM(); }
	void fGetComputerNameExA() { PA = kernel32.oGetComputerNameExA; runASM(); }
	void fGetComputerNameExW() { PA = kernel32.oGetComputerNameExW; runASM(); }
	void fGetComputerNameW() { PA = kernel32.oGetComputerNameW; runASM(); }
	void fGetConsoleAliasA() { PA = kernel32.oGetConsoleAliasA; runASM(); }
	void fGetConsoleAliasExesA() { PA = kernel32.oGetConsoleAliasExesA; runASM(); }
	void fGetConsoleAliasExesLengthA() { PA = kernel32.oGetConsoleAliasExesLengthA; runASM(); }
	void fGetConsoleAliasExesLengthW() { PA = kernel32.oGetConsoleAliasExesLengthW; runASM(); }
	void fGetConsoleAliasExesW() { PA = kernel32.oGetConsoleAliasExesW; runASM(); }
	void fGetConsoleAliasW() { PA = kernel32.oGetConsoleAliasW; runASM(); }
	void fGetConsoleAliasesA() { PA = kernel32.oGetConsoleAliasesA; runASM(); }
	void fGetConsoleAliasesLengthA() { PA = kernel32.oGetConsoleAliasesLengthA; runASM(); }
	void fGetConsoleAliasesLengthW() { PA = kernel32.oGetConsoleAliasesLengthW; runASM(); }
	void fGetConsoleAliasesW() { PA = kernel32.oGetConsoleAliasesW; runASM(); }
	void fGetConsoleCP() { PA = kernel32.oGetConsoleCP; runASM(); }
	void fGetConsoleCharType() { PA = kernel32.oGetConsoleCharType; runASM(); }
	void fGetConsoleCommandHistoryA() { PA = kernel32.oGetConsoleCommandHistoryA; runASM(); }
	void fGetConsoleCommandHistoryLengthA() { PA = kernel32.oGetConsoleCommandHistoryLengthA; runASM(); }
	void fGetConsoleCommandHistoryLengthW() { PA = kernel32.oGetConsoleCommandHistoryLengthW; runASM(); }
	void fGetConsoleCommandHistoryW() { PA = kernel32.oGetConsoleCommandHistoryW; runASM(); }
	void fGetConsoleCursorInfo() { PA = kernel32.oGetConsoleCursorInfo; runASM(); }
	void fGetConsoleCursorMode() { PA = kernel32.oGetConsoleCursorMode; runASM(); }
	void fGetConsoleDisplayMode() { PA = kernel32.oGetConsoleDisplayMode; runASM(); }
	void fGetConsoleFontInfo() { PA = kernel32.oGetConsoleFontInfo; runASM(); }
	void fGetConsoleFontSize() { PA = kernel32.oGetConsoleFontSize; runASM(); }
	void fGetConsoleHardwareState() { PA = kernel32.oGetConsoleHardwareState; runASM(); }
	void fGetConsoleHistoryInfo() { PA = kernel32.oGetConsoleHistoryInfo; runASM(); }
	void fGetConsoleInputExeNameA() { PA = kernel32.oGetConsoleInputExeNameA; runASM(); }
	void fGetConsoleInputExeNameW() { PA = kernel32.oGetConsoleInputExeNameW; runASM(); }
	void fGetConsoleInputWaitHandle() { PA = kernel32.oGetConsoleInputWaitHandle; runASM(); }
	void fGetConsoleKeyboardLayoutNameA() { PA = kernel32.oGetConsoleKeyboardLayoutNameA; runASM(); }
	void fGetConsoleKeyboardLayoutNameW() { PA = kernel32.oGetConsoleKeyboardLayoutNameW; runASM(); }
	void fGetConsoleMode() { PA = kernel32.oGetConsoleMode; runASM(); }
	void fGetConsoleNlsMode() { PA = kernel32.oGetConsoleNlsMode; runASM(); }
	void fGetConsoleOriginalTitleA() { PA = kernel32.oGetConsoleOriginalTitleA; runASM(); }
	void fGetConsoleOriginalTitleW() { PA = kernel32.oGetConsoleOriginalTitleW; runASM(); }
	void fGetConsoleOutputCP() { PA = kernel32.oGetConsoleOutputCP; runASM(); }
	void fGetConsoleProcessList() { PA = kernel32.oGetConsoleProcessList; runASM(); }
	void fGetConsoleScreenBufferInfo() { PA = kernel32.oGetConsoleScreenBufferInfo; runASM(); }
	void fGetConsoleScreenBufferInfoEx() { PA = kernel32.oGetConsoleScreenBufferInfoEx; runASM(); }
	void fGetConsoleSelectionInfo() { PA = kernel32.oGetConsoleSelectionInfo; runASM(); }
	void fGetConsoleTitleA() { PA = kernel32.oGetConsoleTitleA; runASM(); }
	void fGetConsoleTitleW() { PA = kernel32.oGetConsoleTitleW; runASM(); }
	void fGetConsoleWindow() { PA = kernel32.oGetConsoleWindow; runASM(); }
	void fGetCurrencyFormatA() { PA = kernel32.oGetCurrencyFormatA; runASM(); }
	void fGetCurrencyFormatEx() { PA = kernel32.oGetCurrencyFormatEx; runASM(); }
	void fGetCurrencyFormatW() { PA = kernel32.oGetCurrencyFormatW; runASM(); }
	void fGetCurrentActCtx() { PA = kernel32.oGetCurrentActCtx; runASM(); }
	void fGetCurrentActCtxWorker() { PA = kernel32.oGetCurrentActCtxWorker; runASM(); }
	void fGetCurrentApplicationUserModelId() { PA = kernel32.oGetCurrentApplicationUserModelId; runASM(); }
	void fGetCurrentConsoleFont() { PA = kernel32.oGetCurrentConsoleFont; runASM(); }
	void fGetCurrentConsoleFontEx() { PA = kernel32.oGetCurrentConsoleFontEx; runASM(); }
	void fGetCurrentDirectoryA() { PA = kernel32.oGetCurrentDirectoryA; runASM(); }
	void fGetCurrentDirectoryW() { PA = kernel32.oGetCurrentDirectoryW; runASM(); }
	void fGetCurrentPackageFamilyName() { PA = kernel32.oGetCurrentPackageFamilyName; runASM(); }
	void fGetCurrentPackageFullName() { PA = kernel32.oGetCurrentPackageFullName; runASM(); }
	void fGetCurrentPackageId() { PA = kernel32.oGetCurrentPackageId; runASM(); }
	void fGetCurrentPackageInfo() { PA = kernel32.oGetCurrentPackageInfo; runASM(); }
	void fGetCurrentPackagePath() { PA = kernel32.oGetCurrentPackagePath; runASM(); }
	void fGetCurrentProcess() { PA = kernel32.oGetCurrentProcess; runASM(); }
	void fGetCurrentProcessId() { PA = kernel32.oGetCurrentProcessId; runASM(); }
	void fGetCurrentProcessorNumber() { PA = kernel32.oGetCurrentProcessorNumber; runASM(); }
	void fGetCurrentProcessorNumberEx() { PA = kernel32.oGetCurrentProcessorNumberEx; runASM(); }
	void fGetCurrentThread() { PA = kernel32.oGetCurrentThread; runASM(); }
	void fGetCurrentThreadId() { PA = kernel32.oGetCurrentThreadId; runASM(); }
	void fGetCurrentThreadStackLimits() { PA = kernel32.oGetCurrentThreadStackLimits; runASM(); }
	void fGetCurrentUmsThread() { PA = kernel32.oGetCurrentUmsThread; runASM(); }
	void fGetDateFormatA() { PA = kernel32.oGetDateFormatA; runASM(); }
	void fGetDateFormatAWorker() { PA = kernel32.oGetDateFormatAWorker; runASM(); }
	void fGetDateFormatEx() { PA = kernel32.oGetDateFormatEx; runASM(); }
	void fGetDateFormatW() { PA = kernel32.oGetDateFormatW; runASM(); }
	void fGetDateFormatWWorker() { PA = kernel32.oGetDateFormatWWorker; runASM(); }
	void fGetDefaultCommConfigA() { PA = kernel32.oGetDefaultCommConfigA; runASM(); }
	void fGetDefaultCommConfigW() { PA = kernel32.oGetDefaultCommConfigW; runASM(); }
	void fGetDevicePowerState() { PA = kernel32.oGetDevicePowerState; runASM(); }
	void fGetDiskFreeSpaceA() { PA = kernel32.oGetDiskFreeSpaceA; runASM(); }
	void fGetDiskFreeSpaceExA() { PA = kernel32.oGetDiskFreeSpaceExA; runASM(); }
	void fGetDiskFreeSpaceExW() { PA = kernel32.oGetDiskFreeSpaceExW; runASM(); }
	void fGetDiskFreeSpaceW() { PA = kernel32.oGetDiskFreeSpaceW; runASM(); }
	void fGetDiskSpaceInformationA() { PA = kernel32.oGetDiskSpaceInformationA; runASM(); }
	void fGetDiskSpaceInformationW() { PA = kernel32.oGetDiskSpaceInformationW; runASM(); }
	void fGetDllDirectoryA() { PA = kernel32.oGetDllDirectoryA; runASM(); }
	void fGetDllDirectoryW() { PA = kernel32.oGetDllDirectoryW; runASM(); }
	void fGetDriveTypeA() { PA = kernel32.oGetDriveTypeA; runASM(); }
	void fGetDriveTypeW() { PA = kernel32.oGetDriveTypeW; runASM(); }
	void fGetDurationFormat() { PA = kernel32.oGetDurationFormat; runASM(); }
	void fGetDurationFormatEx() { PA = kernel32.oGetDurationFormatEx; runASM(); }
	void fGetDynamicTimeZoneInformation() { PA = kernel32.oGetDynamicTimeZoneInformation; runASM(); }
	void fGetEnabledXStateFeatures() { PA = kernel32.oGetEnabledXStateFeatures; runASM(); }
	void fGetEncryptedFileVersionExt() { PA = kernel32.oGetEncryptedFileVersionExt; runASM(); }
	void fGetEnvironmentStrings() { PA = kernel32.oGetEnvironmentStrings; runASM(); }
	void fGetEnvironmentStringsA() { PA = kernel32.oGetEnvironmentStringsA; runASM(); }
	void fGetEnvironmentStringsW() { PA = kernel32.oGetEnvironmentStringsW; runASM(); }
	void fGetEnvironmentVariableA() { PA = kernel32.oGetEnvironmentVariableA; runASM(); }
	void fGetEnvironmentVariableW() { PA = kernel32.oGetEnvironmentVariableW; runASM(); }
	void fGetEraNameCountedString() { PA = kernel32.oGetEraNameCountedString; runASM(); }
	void fGetErrorMode() { PA = kernel32.oGetErrorMode; runASM(); }
	void fGetExitCodeProcess() { PA = kernel32.oGetExitCodeProcess; runASM(); }
	void fGetExitCodeThread() { PA = kernel32.oGetExitCodeThread; runASM(); }
	void fGetExpandedNameA() { PA = kernel32.oGetExpandedNameA; runASM(); }
	void fGetExpandedNameW() { PA = kernel32.oGetExpandedNameW; runASM(); }
	void fGetFileAttributesA() { PA = kernel32.oGetFileAttributesA; runASM(); }
	void fGetFileAttributesExA() { PA = kernel32.oGetFileAttributesExA; runASM(); }
	void fGetFileAttributesExW() { PA = kernel32.oGetFileAttributesExW; runASM(); }
	void fGetFileAttributesTransactedA() { PA = kernel32.oGetFileAttributesTransactedA; runASM(); }
	void fGetFileAttributesTransactedW() { PA = kernel32.oGetFileAttributesTransactedW; runASM(); }
	void fGetFileAttributesW() { PA = kernel32.oGetFileAttributesW; runASM(); }
	void fGetFileBandwidthReservation() { PA = kernel32.oGetFileBandwidthReservation; runASM(); }
	void fGetFileInformationByHandle() { PA = kernel32.oGetFileInformationByHandle; runASM(); }
	void fGetFileInformationByHandleEx() { PA = kernel32.oGetFileInformationByHandleEx; runASM(); }
	void fGetFileMUIInfo() { PA = kernel32.oGetFileMUIInfo; runASM(); }
	void fGetFileMUIPath() { PA = kernel32.oGetFileMUIPath; runASM(); }
	void fGetFileSize() { PA = kernel32.oGetFileSize; runASM(); }
	void fGetFileSizeEx() { PA = kernel32.oGetFileSizeEx; runASM(); }
	void fGetFileTime() { PA = kernel32.oGetFileTime; runASM(); }
	void fGetFileType() { PA = kernel32.oGetFileType; runASM(); }
	void fGetFinalPathNameByHandleA() { PA = kernel32.oGetFinalPathNameByHandleA; runASM(); }
	void fGetFinalPathNameByHandleW() { PA = kernel32.oGetFinalPathNameByHandleW; runASM(); }
	void fGetFirmwareEnvironmentVariableA() { PA = kernel32.oGetFirmwareEnvironmentVariableA; runASM(); }
	void fGetFirmwareEnvironmentVariableExA() { PA = kernel32.oGetFirmwareEnvironmentVariableExA; runASM(); }
	void fGetFirmwareEnvironmentVariableExW() { PA = kernel32.oGetFirmwareEnvironmentVariableExW; runASM(); }
	void fGetFirmwareEnvironmentVariableW() { PA = kernel32.oGetFirmwareEnvironmentVariableW; runASM(); }
	void fGetFirmwareType() { PA = kernel32.oGetFirmwareType; runASM(); }
	void fGetFullPathNameA() { PA = kernel32.oGetFullPathNameA; runASM(); }
	void fGetFullPathNameTransactedA() { PA = kernel32.oGetFullPathNameTransactedA; runASM(); }
	void fGetFullPathNameTransactedW() { PA = kernel32.oGetFullPathNameTransactedW; runASM(); }
	void fGetFullPathNameW() { PA = kernel32.oGetFullPathNameW; runASM(); }
	void fGetGeoInfoA() { PA = kernel32.oGetGeoInfoA; runASM(); }
	void fGetGeoInfoEx() { PA = kernel32.oGetGeoInfoEx; runASM(); }
	void fGetGeoInfoW() { PA = kernel32.oGetGeoInfoW; runASM(); }
	void fGetHandleInformation() { PA = kernel32.oGetHandleInformation; runASM(); }
	void fGetLargePageMinimum() { PA = kernel32.oGetLargePageMinimum; runASM(); }
	void fGetLargestConsoleWindowSize() { PA = kernel32.oGetLargestConsoleWindowSize; runASM(); }
	void fGetLastError() { PA = kernel32.oGetLastError; runASM(); }
	void fGetLocalTime() { PA = kernel32.oGetLocalTime; runASM(); }
	void fGetLocaleInfoA() { PA = kernel32.oGetLocaleInfoA; runASM(); }
	void fGetLocaleInfoEx() { PA = kernel32.oGetLocaleInfoEx; runASM(); }
	void fGetLocaleInfoW() { PA = kernel32.oGetLocaleInfoW; runASM(); }
	void fGetLogicalDriveStringsA() { PA = kernel32.oGetLogicalDriveStringsA; runASM(); }
	void fGetLogicalDriveStringsW() { PA = kernel32.oGetLogicalDriveStringsW; runASM(); }
	void fGetLogicalDrives() { PA = kernel32.oGetLogicalDrives; runASM(); }
	void fGetLogicalProcessorInformation() { PA = kernel32.oGetLogicalProcessorInformation; runASM(); }
	void fGetLogicalProcessorInformationEx() { PA = kernel32.oGetLogicalProcessorInformationEx; runASM(); }
	void fGetLongPathNameA() { PA = kernel32.oGetLongPathNameA; runASM(); }
	void fGetLongPathNameTransactedA() { PA = kernel32.oGetLongPathNameTransactedA; runASM(); }
	void fGetLongPathNameTransactedW() { PA = kernel32.oGetLongPathNameTransactedW; runASM(); }
	void fGetLongPathNameW() { PA = kernel32.oGetLongPathNameW; runASM(); }
	void fGetMailslotInfo() { PA = kernel32.oGetMailslotInfo; runASM(); }
	void fGetMaximumProcessorCount() { PA = kernel32.oGetMaximumProcessorCount; runASM(); }
	void fGetMaximumProcessorGroupCount() { PA = kernel32.oGetMaximumProcessorGroupCount; runASM(); }
	void fGetMemoryErrorHandlingCapabilities() { PA = kernel32.oGetMemoryErrorHandlingCapabilities; runASM(); }
	void fGetModuleFileNameA() { PA = kernel32.oGetModuleFileNameA; runASM(); }
	void fGetModuleFileNameW() { PA = kernel32.oGetModuleFileNameW; runASM(); }
	void fGetModuleHandleA() { PA = kernel32.oGetModuleHandleA; runASM(); }
	void fGetModuleHandleExA() { PA = kernel32.oGetModuleHandleExA; runASM(); }
	void fGetModuleHandleExW() { PA = kernel32.oGetModuleHandleExW; runASM(); }
	void fGetModuleHandleW() { PA = kernel32.oGetModuleHandleW; runASM(); }
	void fGetNLSVersion() { PA = kernel32.oGetNLSVersion; runASM(); }
	void fGetNLSVersionEx() { PA = kernel32.oGetNLSVersionEx; runASM(); }
	void fGetNamedPipeAttribute() { PA = kernel32.oGetNamedPipeAttribute; runASM(); }
	void fGetNamedPipeClientComputerNameA() { PA = kernel32.oGetNamedPipeClientComputerNameA; runASM(); }
	void fGetNamedPipeClientComputerNameW() { PA = kernel32.oGetNamedPipeClientComputerNameW; runASM(); }
	void fGetNamedPipeClientProcessId() { PA = kernel32.oGetNamedPipeClientProcessId; runASM(); }
	void fGetNamedPipeClientSessionId() { PA = kernel32.oGetNamedPipeClientSessionId; runASM(); }
	void fGetNamedPipeHandleStateA() { PA = kernel32.oGetNamedPipeHandleStateA; runASM(); }
	void fGetNamedPipeHandleStateW() { PA = kernel32.oGetNamedPipeHandleStateW; runASM(); }
	void fGetNamedPipeInfo() { PA = kernel32.oGetNamedPipeInfo; runASM(); }
	void fGetNamedPipeServerProcessId() { PA = kernel32.oGetNamedPipeServerProcessId; runASM(); }
	void fGetNamedPipeServerSessionId() { PA = kernel32.oGetNamedPipeServerSessionId; runASM(); }
	void fGetNativeSystemInfo() { PA = kernel32.oGetNativeSystemInfo; runASM(); }
	void fGetNextUmsListItem() { PA = kernel32.oGetNextUmsListItem; runASM(); }
	void fGetNextVDMCommand() { PA = kernel32.oGetNextVDMCommand; runASM(); }
	void fGetNumaAvailableMemoryNode() { PA = kernel32.oGetNumaAvailableMemoryNode; runASM(); }
	void fGetNumaAvailableMemoryNodeEx() { PA = kernel32.oGetNumaAvailableMemoryNodeEx; runASM(); }
	void fGetNumaHighestNodeNumber() { PA = kernel32.oGetNumaHighestNodeNumber; runASM(); }
	void fGetNumaNodeNumberFromHandle() { PA = kernel32.oGetNumaNodeNumberFromHandle; runASM(); }
	void fGetNumaNodeProcessorMask() { PA = kernel32.oGetNumaNodeProcessorMask; runASM(); }
	void fGetNumaNodeProcessorMaskEx() { PA = kernel32.oGetNumaNodeProcessorMaskEx; runASM(); }
	void fGetNumaProcessorNode() { PA = kernel32.oGetNumaProcessorNode; runASM(); }
	void fGetNumaProcessorNodeEx() { PA = kernel32.oGetNumaProcessorNodeEx; runASM(); }
	void fGetNumaProximityNode() { PA = kernel32.oGetNumaProximityNode; runASM(); }
	void fGetNumaProximityNodeEx() { PA = kernel32.oGetNumaProximityNodeEx; runASM(); }
	void fGetNumberFormatA() { PA = kernel32.oGetNumberFormatA; runASM(); }
	void fGetNumberFormatEx() { PA = kernel32.oGetNumberFormatEx; runASM(); }
	void fGetNumberFormatW() { PA = kernel32.oGetNumberFormatW; runASM(); }
	void fGetNumberOfConsoleFonts() { PA = kernel32.oGetNumberOfConsoleFonts; runASM(); }
	void fGetNumberOfConsoleInputEvents() { PA = kernel32.oGetNumberOfConsoleInputEvents; runASM(); }
	void fGetNumberOfConsoleMouseButtons() { PA = kernel32.oGetNumberOfConsoleMouseButtons; runASM(); }
	void fGetOEMCP() { PA = kernel32.oGetOEMCP; runASM(); }
	void fGetOverlappedResult() { PA = kernel32.oGetOverlappedResult; runASM(); }
	void fGetOverlappedResultEx() { PA = kernel32.oGetOverlappedResultEx; runASM(); }
	void fGetPackageApplicationIds() { PA = kernel32.oGetPackageApplicationIds; runASM(); }
	void fGetPackageFamilyName() { PA = kernel32.oGetPackageFamilyName; runASM(); }
	void fGetPackageFullName() { PA = kernel32.oGetPackageFullName; runASM(); }
	void fGetPackageId() { PA = kernel32.oGetPackageId; runASM(); }
	void fGetPackageInfo() { PA = kernel32.oGetPackageInfo; runASM(); }
	void fGetPackagePath() { PA = kernel32.oGetPackagePath; runASM(); }
	void fGetPackagePathByFullName() { PA = kernel32.oGetPackagePathByFullName; runASM(); }
	void fGetPackagesByPackageFamily() { PA = kernel32.oGetPackagesByPackageFamily; runASM(); }
	void fGetPhysicallyInstalledSystemMemory() { PA = kernel32.oGetPhysicallyInstalledSystemMemory; runASM(); }
	void fGetPriorityClass() { PA = kernel32.oGetPriorityClass; runASM(); }
	void fGetPrivateProfileIntA() { PA = kernel32.oGetPrivateProfileIntA; runASM(); }
	void fGetPrivateProfileIntW() { PA = kernel32.oGetPrivateProfileIntW; runASM(); }
	void fGetPrivateProfileSectionA() { PA = kernel32.oGetPrivateProfileSectionA; runASM(); }
	void fGetPrivateProfileSectionNamesA() { PA = kernel32.oGetPrivateProfileSectionNamesA; runASM(); }
	void fGetPrivateProfileSectionNamesW() { PA = kernel32.oGetPrivateProfileSectionNamesW; runASM(); }
	void fGetPrivateProfileSectionW() { PA = kernel32.oGetPrivateProfileSectionW; runASM(); }
	void fGetPrivateProfileStringA() { PA = kernel32.oGetPrivateProfileStringA; runASM(); }
	void fGetPrivateProfileStringW() { PA = kernel32.oGetPrivateProfileStringW; runASM(); }
	void fGetPrivateProfileStructA() { PA = kernel32.oGetPrivateProfileStructA; runASM(); }
	void fGetPrivateProfileStructW() { PA = kernel32.oGetPrivateProfileStructW; runASM(); }
	void fGetProcAddress() { PA = kernel32.oGetProcAddress; runASM(); }
	void fGetProcessAffinityMask() { PA = kernel32.oGetProcessAffinityMask; runASM(); }
	void fGetProcessDEPPolicy() { PA = kernel32.oGetProcessDEPPolicy; runASM(); }
	void fGetProcessDefaultCpuSets() { PA = kernel32.oGetProcessDefaultCpuSets; runASM(); }
	void fGetProcessGroupAffinity() { PA = kernel32.oGetProcessGroupAffinity; runASM(); }
	void fGetProcessHandleCount() { PA = kernel32.oGetProcessHandleCount; runASM(); }
	void fGetProcessHeap() { PA = kernel32.oGetProcessHeap; runASM(); }
	void fGetProcessHeaps() { PA = kernel32.oGetProcessHeaps; runASM(); }
	void fGetProcessId() { PA = kernel32.oGetProcessId; runASM(); }
	void fGetProcessIdOfThread() { PA = kernel32.oGetProcessIdOfThread; runASM(); }
	void fGetProcessInformation() { PA = kernel32.oGetProcessInformation; runASM(); }
	void fGetProcessIoCounters() { PA = kernel32.oGetProcessIoCounters; runASM(); }
	void fGetProcessMitigationPolicy() { PA = kernel32.oGetProcessMitigationPolicy; runASM(); }
	void fGetProcessPreferredUILanguages() { PA = kernel32.oGetProcessPreferredUILanguages; runASM(); }
	void fGetProcessPriorityBoost() { PA = kernel32.oGetProcessPriorityBoost; runASM(); }
	void fGetProcessShutdownParameters() { PA = kernel32.oGetProcessShutdownParameters; runASM(); }
	void fGetProcessTimes() { PA = kernel32.oGetProcessTimes; runASM(); }
	void fGetProcessVersion() { PA = kernel32.oGetProcessVersion; runASM(); }
	void fGetProcessWorkingSetSize() { PA = kernel32.oGetProcessWorkingSetSize; runASM(); }
	void fGetProcessWorkingSetSizeEx() { PA = kernel32.oGetProcessWorkingSetSizeEx; runASM(); }
	void fGetProcessorSystemCycleTime() { PA = kernel32.oGetProcessorSystemCycleTime; runASM(); }
	void fGetProductInfo() { PA = kernel32.oGetProductInfo; runASM(); }
	void fGetProfileIntA() { PA = kernel32.oGetProfileIntA; runASM(); }
	void fGetProfileIntW() { PA = kernel32.oGetProfileIntW; runASM(); }
	void fGetProfileSectionA() { PA = kernel32.oGetProfileSectionA; runASM(); }
	void fGetProfileSectionW() { PA = kernel32.oGetProfileSectionW; runASM(); }
	void fGetProfileStringA() { PA = kernel32.oGetProfileStringA; runASM(); }
	void fGetProfileStringW() { PA = kernel32.oGetProfileStringW; runASM(); }
	void fGetQueuedCompletionStatus() { PA = kernel32.oGetQueuedCompletionStatus; runASM(); }
	void fGetQueuedCompletionStatusEx() { PA = kernel32.oGetQueuedCompletionStatusEx; runASM(); }
	void fGetShortPathNameA() { PA = kernel32.oGetShortPathNameA; runASM(); }
	void fGetShortPathNameW() { PA = kernel32.oGetShortPathNameW; runASM(); }
	void fGetStagedPackagePathByFullName() { PA = kernel32.oGetStagedPackagePathByFullName; runASM(); }
	void fGetStartupInfoA() { PA = kernel32.oGetStartupInfoA; runASM(); }
	void fGetStartupInfoW() { PA = kernel32.oGetStartupInfoW; runASM(); }
	void fGetStateFolder() { PA = kernel32.oGetStateFolder; runASM(); }
	void fGetStdHandle() { PA = kernel32.oGetStdHandle; runASM(); }
	void fGetStringScripts() { PA = kernel32.oGetStringScripts; runASM(); }
	void fGetStringTypeA() { PA = kernel32.oGetStringTypeA; runASM(); }
	void fGetStringTypeExA() { PA = kernel32.oGetStringTypeExA; runASM(); }
	void fGetStringTypeExW() { PA = kernel32.oGetStringTypeExW; runASM(); }
	void fGetStringTypeW() { PA = kernel32.oGetStringTypeW; runASM(); }
	void fGetSystemAppDataKey() { PA = kernel32.oGetSystemAppDataKey; runASM(); }
	void fGetSystemCpuSetInformation() { PA = kernel32.oGetSystemCpuSetInformation; runASM(); }
	void fGetSystemDEPPolicy() { PA = kernel32.oGetSystemDEPPolicy; runASM(); }
	void fGetSystemDefaultLCID() { PA = kernel32.oGetSystemDefaultLCID; runASM(); }
	void fGetSystemDefaultLangID() { PA = kernel32.oGetSystemDefaultLangID; runASM(); }
	void fGetSystemDefaultLocaleName() { PA = kernel32.oGetSystemDefaultLocaleName; runASM(); }
	void fGetSystemDefaultUILanguage() { PA = kernel32.oGetSystemDefaultUILanguage; runASM(); }
	void fGetSystemDirectoryA() { PA = kernel32.oGetSystemDirectoryA; runASM(); }
	void fGetSystemDirectoryW() { PA = kernel32.oGetSystemDirectoryW; runASM(); }
	void fGetSystemFileCacheSize() { PA = kernel32.oGetSystemFileCacheSize; runASM(); }
	void fGetSystemFirmwareTable() { PA = kernel32.oGetSystemFirmwareTable; runASM(); }
	void fGetSystemInfo() { PA = kernel32.oGetSystemInfo; runASM(); }
	void fGetSystemPowerStatus() { PA = kernel32.oGetSystemPowerStatus; runASM(); }
	void fGetSystemPreferredUILanguages() { PA = kernel32.oGetSystemPreferredUILanguages; runASM(); }
	void fGetSystemRegistryQuota() { PA = kernel32.oGetSystemRegistryQuota; runASM(); }
	void fGetSystemTime() { PA = kernel32.oGetSystemTime; runASM(); }
	void fGetSystemTimeAdjustment() { PA = kernel32.oGetSystemTimeAdjustment; runASM(); }
	void fGetSystemTimeAsFileTime() { PA = kernel32.oGetSystemTimeAsFileTime; runASM(); }
	void fGetSystemTimePreciseAsFileTime() { PA = kernel32.oGetSystemTimePreciseAsFileTime; runASM(); }
	void fGetSystemTimes() { PA = kernel32.oGetSystemTimes; runASM(); }
	void fGetSystemWindowsDirectoryA() { PA = kernel32.oGetSystemWindowsDirectoryA; runASM(); }
	void fGetSystemWindowsDirectoryW() { PA = kernel32.oGetSystemWindowsDirectoryW; runASM(); }
	void fGetSystemWow64DirectoryA() { PA = kernel32.oGetSystemWow64DirectoryA; runASM(); }
	void fGetSystemWow64DirectoryW() { PA = kernel32.oGetSystemWow64DirectoryW; runASM(); }
	void fGetTapeParameters() { PA = kernel32.oGetTapeParameters; runASM(); }
	void fGetTapePosition() { PA = kernel32.oGetTapePosition; runASM(); }
	void fGetTapeStatus() { PA = kernel32.oGetTapeStatus; runASM(); }
	void fGetTempFileNameA() { PA = kernel32.oGetTempFileNameA; runASM(); }
	void fGetTempFileNameW() { PA = kernel32.oGetTempFileNameW; runASM(); }
	void fGetTempPathA() { PA = kernel32.oGetTempPathA; runASM(); }
	void fGetTempPathW() { PA = kernel32.oGetTempPathW; runASM(); }
	void fGetThreadContext() { PA = kernel32.oGetThreadContext; runASM(); }
	void fGetThreadDescription() { PA = kernel32.oGetThreadDescription; runASM(); }
	void fGetThreadErrorMode() { PA = kernel32.oGetThreadErrorMode; runASM(); }
	void fGetThreadGroupAffinity() { PA = kernel32.oGetThreadGroupAffinity; runASM(); }
	void fGetThreadIOPendingFlag() { PA = kernel32.oGetThreadIOPendingFlag; runASM(); }
	void fGetThreadId() { PA = kernel32.oGetThreadId; runASM(); }
	void fGetThreadIdealProcessorEx() { PA = kernel32.oGetThreadIdealProcessorEx; runASM(); }
	void fGetThreadInformation() { PA = kernel32.oGetThreadInformation; runASM(); }
	void fGetThreadLocale() { PA = kernel32.oGetThreadLocale; runASM(); }
	void fGetThreadPreferredUILanguages() { PA = kernel32.oGetThreadPreferredUILanguages; runASM(); }
	void fGetThreadPriority() { PA = kernel32.oGetThreadPriority; runASM(); }
	void fGetThreadPriorityBoost() { PA = kernel32.oGetThreadPriorityBoost; runASM(); }
	void fGetThreadSelectedCpuSets() { PA = kernel32.oGetThreadSelectedCpuSets; runASM(); }
	void fGetThreadSelectorEntry() { PA = kernel32.oGetThreadSelectorEntry; runASM(); }
	void fGetThreadTimes() { PA = kernel32.oGetThreadTimes; runASM(); }
	void fGetThreadUILanguage() { PA = kernel32.oGetThreadUILanguage; runASM(); }
	void fGetTickCount() { PA = kernel32.oGetTickCount; runASM(); }
	void fGetTickCount64() { PA = kernel32.oGetTickCount64; runASM(); }
	void fGetTimeFormatA() { PA = kernel32.oGetTimeFormatA; runASM(); }
	void fGetTimeFormatAWorker() { PA = kernel32.oGetTimeFormatAWorker; runASM(); }
	void fGetTimeFormatEx() { PA = kernel32.oGetTimeFormatEx; runASM(); }
	void fGetTimeFormatW() { PA = kernel32.oGetTimeFormatW; runASM(); }
	void fGetTimeFormatWWorker() { PA = kernel32.oGetTimeFormatWWorker; runASM(); }
	void fGetTimeZoneInformation() { PA = kernel32.oGetTimeZoneInformation; runASM(); }
	void fGetTimeZoneInformationForYear() { PA = kernel32.oGetTimeZoneInformationForYear; runASM(); }
	void fGetUILanguageInfo() { PA = kernel32.oGetUILanguageInfo; runASM(); }
	void fGetUmsCompletionListEvent() { PA = kernel32.oGetUmsCompletionListEvent; runASM(); }
	void fGetUmsSystemThreadInformation() { PA = kernel32.oGetUmsSystemThreadInformation; runASM(); }
	void fGetUserDefaultGeoName() { PA = kernel32.oGetUserDefaultGeoName; runASM(); }
	void fGetUserDefaultLCID() { PA = kernel32.oGetUserDefaultLCID; runASM(); }
	void fGetUserDefaultLangID() { PA = kernel32.oGetUserDefaultLangID; runASM(); }
	void fGetUserDefaultLocaleName() { PA = kernel32.oGetUserDefaultLocaleName; runASM(); }
	void fGetUserDefaultUILanguage() { PA = kernel32.oGetUserDefaultUILanguage; runASM(); }
	void fGetUserGeoID() { PA = kernel32.oGetUserGeoID; runASM(); }
	void fGetUserPreferredUILanguages() { PA = kernel32.oGetUserPreferredUILanguages; runASM(); }
	void fGetVDMCurrentDirectories() { PA = kernel32.oGetVDMCurrentDirectories; runASM(); }
	void fGetVersion() { PA = kernel32.oGetVersion; runASM(); }
	void fGetVersionExA() { PA = kernel32.oGetVersionExA; runASM(); }
	void fGetVersionExW() { PA = kernel32.oGetVersionExW; runASM(); }
	void fGetVolumeInformationA() { PA = kernel32.oGetVolumeInformationA; runASM(); }
	void fGetVolumeInformationByHandleW() { PA = kernel32.oGetVolumeInformationByHandleW; runASM(); }
	void fGetVolumeInformationW() { PA = kernel32.oGetVolumeInformationW; runASM(); }
	void fGetVolumeNameForVolumeMountPointA() { PA = kernel32.oGetVolumeNameForVolumeMountPointA; runASM(); }
	void fGetVolumeNameForVolumeMountPointW() { PA = kernel32.oGetVolumeNameForVolumeMountPointW; runASM(); }
	void fGetVolumePathNameA() { PA = kernel32.oGetVolumePathNameA; runASM(); }
	void fGetVolumePathNameW() { PA = kernel32.oGetVolumePathNameW; runASM(); }
	void fGetVolumePathNamesForVolumeNameA() { PA = kernel32.oGetVolumePathNamesForVolumeNameA; runASM(); }
	void fGetVolumePathNamesForVolumeNameW() { PA = kernel32.oGetVolumePathNamesForVolumeNameW; runASM(); }
	void fGetWindowsDirectoryA() { PA = kernel32.oGetWindowsDirectoryA; runASM(); }
	void fGetWindowsDirectoryW() { PA = kernel32.oGetWindowsDirectoryW; runASM(); }
	void fGetWriteWatch() { PA = kernel32.oGetWriteWatch; runASM(); }
	void fGetXStateFeaturesMask() { PA = kernel32.oGetXStateFeaturesMask; runASM(); }
	void fGlobalAddAtomA() { PA = kernel32.oGlobalAddAtomA; runASM(); }
	void fGlobalAddAtomExA() { PA = kernel32.oGlobalAddAtomExA; runASM(); }
	void fGlobalAddAtomExW() { PA = kernel32.oGlobalAddAtomExW; runASM(); }
	void fGlobalAddAtomW() { PA = kernel32.oGlobalAddAtomW; runASM(); }
	void fGlobalAlloc() { PA = kernel32.oGlobalAlloc; runASM(); }
	void fGlobalCompact() { PA = kernel32.oGlobalCompact; runASM(); }
	void fGlobalDeleteAtom() { PA = kernel32.oGlobalDeleteAtom; runASM(); }
	void fGlobalFindAtomA() { PA = kernel32.oGlobalFindAtomA; runASM(); }
	void fGlobalFindAtomW() { PA = kernel32.oGlobalFindAtomW; runASM(); }
	void fGlobalFix() { PA = kernel32.oGlobalFix; runASM(); }
	void fGlobalFlags() { PA = kernel32.oGlobalFlags; runASM(); }
	void fGlobalFree() { PA = kernel32.oGlobalFree; runASM(); }
	void fGlobalGetAtomNameA() { PA = kernel32.oGlobalGetAtomNameA; runASM(); }
	void fGlobalGetAtomNameW() { PA = kernel32.oGlobalGetAtomNameW; runASM(); }
	void fGlobalHandle() { PA = kernel32.oGlobalHandle; runASM(); }
	void fGlobalLock() { PA = kernel32.oGlobalLock; runASM(); }
	void fGlobalMemoryStatus() { PA = kernel32.oGlobalMemoryStatus; runASM(); }
	void fGlobalMemoryStatusEx() { PA = kernel32.oGlobalMemoryStatusEx; runASM(); }
	void fGlobalReAlloc() { PA = kernel32.oGlobalReAlloc; runASM(); }
	void fGlobalSize() { PA = kernel32.oGlobalSize; runASM(); }
	void fGlobalUnWire() { PA = kernel32.oGlobalUnWire; runASM(); }
	void fGlobalUnfix() { PA = kernel32.oGlobalUnfix; runASM(); }
	void fGlobalUnlock() { PA = kernel32.oGlobalUnlock; runASM(); }
	void fGlobalWire() { PA = kernel32.oGlobalWire; runASM(); }
	void fHeap32First() { PA = kernel32.oHeap32First; runASM(); }
	void fHeap32ListFirst() { PA = kernel32.oHeap32ListFirst; runASM(); }
	void fHeap32ListNext() { PA = kernel32.oHeap32ListNext; runASM(); }
	void fHeap32Next() { PA = kernel32.oHeap32Next; runASM(); }
	void fHeapAlloc() { PA = kernel32.oHeapAlloc; runASM(); }
	void fHeapCompact() { PA = kernel32.oHeapCompact; runASM(); }
	void fHeapCreate() { PA = kernel32.oHeapCreate; runASM(); }
	void fHeapDestroy() { PA = kernel32.oHeapDestroy; runASM(); }
	void fHeapFree() { PA = kernel32.oHeapFree; runASM(); }
	void fHeapLock() { PA = kernel32.oHeapLock; runASM(); }
	void fHeapQueryInformation() { PA = kernel32.oHeapQueryInformation; runASM(); }
	void fHeapReAlloc() { PA = kernel32.oHeapReAlloc; runASM(); }
	void fHeapSetInformation() { PA = kernel32.oHeapSetInformation; runASM(); }
	void fHeapSize() { PA = kernel32.oHeapSize; runASM(); }
	void fHeapSummary() { PA = kernel32.oHeapSummary; runASM(); }
	void fHeapUnlock() { PA = kernel32.oHeapUnlock; runASM(); }
	void fHeapValidate() { PA = kernel32.oHeapValidate; runASM(); }
	void fHeapWalk() { PA = kernel32.oHeapWalk; runASM(); }
	void fIdnToAscii() { PA = kernel32.oIdnToAscii; runASM(); }
	void fIdnToNameprepUnicode() { PA = kernel32.oIdnToNameprepUnicode; runASM(); }
	void fIdnToUnicode() { PA = kernel32.oIdnToUnicode; runASM(); }
	void fInitAtomTable() { PA = kernel32.oInitAtomTable; runASM(); }
	void fInitOnceBeginInitialize() { PA = kernel32.oInitOnceBeginInitialize; runASM(); }
	void fInitOnceComplete() { PA = kernel32.oInitOnceComplete; runASM(); }
	void fInitOnceExecuteOnce() { PA = kernel32.oInitOnceExecuteOnce; runASM(); }
	void fInitOnceInitialize() { PA = kernel32.oInitOnceInitialize; runASM(); }
	void fInitializeConditionVariable() { PA = kernel32.oInitializeConditionVariable; runASM(); }
	void fInitializeContext() { PA = kernel32.oInitializeContext; runASM(); }
	void fInitializeContext2() { PA = kernel32.oInitializeContext2; runASM(); }
	void fInitializeCriticalSection() { PA = kernel32.oInitializeCriticalSection; runASM(); }
	void fInitializeCriticalSectionAndSpinCount() { PA = kernel32.oInitializeCriticalSectionAndSpinCount; runASM(); }
	void fInitializeCriticalSectionEx() { PA = kernel32.oInitializeCriticalSectionEx; runASM(); }
	void fInitializeEnclave() { PA = kernel32.oInitializeEnclave; runASM(); }
	void fInitializeProcThreadAttributeList() { PA = kernel32.oInitializeProcThreadAttributeList; runASM(); }
	void fInitializeSListHead() { PA = kernel32.oInitializeSListHead; runASM(); }
	void fInitializeSRWLock() { PA = kernel32.oInitializeSRWLock; runASM(); }
	void fInitializeSynchronizationBarrier() { PA = kernel32.oInitializeSynchronizationBarrier; runASM(); }
	void fInstallELAMCertificateInfo() { PA = kernel32.oInstallELAMCertificateInfo; runASM(); }
	void fInterlockedFlushSList() { PA = kernel32.oInterlockedFlushSList; runASM(); }
	void fInterlockedPopEntrySList() { PA = kernel32.oInterlockedPopEntrySList; runASM(); }
	void fInterlockedPushEntrySList() { PA = kernel32.oInterlockedPushEntrySList; runASM(); }
	void fInterlockedPushListSList() { PA = kernel32.oInterlockedPushListSList; runASM(); }
	void fInterlockedPushListSListEx() { PA = kernel32.oInterlockedPushListSListEx; runASM(); }
	void fInvalidateConsoleDIBits() { PA = kernel32.oInvalidateConsoleDIBits; runASM(); }
	void fIsBadCodePtr() { PA = kernel32.oIsBadCodePtr; runASM(); }
	void fIsBadHugeReadPtr() { PA = kernel32.oIsBadHugeReadPtr; runASM(); }
	void fIsBadHugeWritePtr() { PA = kernel32.oIsBadHugeWritePtr; runASM(); }
	void fIsBadReadPtr() { PA = kernel32.oIsBadReadPtr; runASM(); }
	void fIsBadStringPtrA() { PA = kernel32.oIsBadStringPtrA; runASM(); }
	void fIsBadStringPtrW() { PA = kernel32.oIsBadStringPtrW; runASM(); }
	void fIsBadWritePtr() { PA = kernel32.oIsBadWritePtr; runASM(); }
	void fIsCalendarLeapDay() { PA = kernel32.oIsCalendarLeapDay; runASM(); }
	void fIsCalendarLeapMonth() { PA = kernel32.oIsCalendarLeapMonth; runASM(); }
	void fIsCalendarLeapYear() { PA = kernel32.oIsCalendarLeapYear; runASM(); }
	void fIsDBCSLeadByte() { PA = kernel32.oIsDBCSLeadByte; runASM(); }
	void fIsDBCSLeadByteEx() { PA = kernel32.oIsDBCSLeadByteEx; runASM(); }
	void fIsDebuggerPresent() { PA = kernel32.oIsDebuggerPresent; runASM(); }
	void fIsEnclaveTypeSupported() { PA = kernel32.oIsEnclaveTypeSupported; runASM(); }
	void fIsNLSDefinedString() { PA = kernel32.oIsNLSDefinedString; runASM(); }
	void fIsNativeVhdBoot() { PA = kernel32.oIsNativeVhdBoot; runASM(); }
	void fIsNormalizedString() { PA = kernel32.oIsNormalizedString; runASM(); }
	void fIsProcessCritical() { PA = kernel32.oIsProcessCritical; runASM(); }
	void fIsProcessInJob() { PA = kernel32.oIsProcessInJob; runASM(); }
	void fIsProcessorFeaturePresent() { PA = kernel32.oIsProcessorFeaturePresent; runASM(); }
	void fIsSystemResumeAutomatic() { PA = kernel32.oIsSystemResumeAutomatic; runASM(); }
	void fIsThreadAFiber() { PA = kernel32.oIsThreadAFiber; runASM(); }
	void fIsThreadpoolTimerSet() { PA = kernel32.oIsThreadpoolTimerSet; runASM(); }
	void fIsValidCalDateTime() { PA = kernel32.oIsValidCalDateTime; runASM(); }
	void fIsValidCodePage() { PA = kernel32.oIsValidCodePage; runASM(); }
	void fIsValidLanguageGroup() { PA = kernel32.oIsValidLanguageGroup; runASM(); }
	void fIsValidLocale() { PA = kernel32.oIsValidLocale; runASM(); }
	void fIsValidLocaleName() { PA = kernel32.oIsValidLocaleName; runASM(); }
	void fIsValidNLSVersion() { PA = kernel32.oIsValidNLSVersion; runASM(); }
	void fIsWow64GuestMachineSupported() { PA = kernel32.oIsWow64GuestMachineSupported; runASM(); }
	void fIsWow64Process() { PA = kernel32.oIsWow64Process; runASM(); }
	void fIsWow64Process2() { PA = kernel32.oIsWow64Process2; runASM(); }
	void fK32EmptyWorkingSet() { PA = kernel32.oK32EmptyWorkingSet; runASM(); }
	void fK32EnumDeviceDrivers() { PA = kernel32.oK32EnumDeviceDrivers; runASM(); }
	void fK32EnumPageFilesA() { PA = kernel32.oK32EnumPageFilesA; runASM(); }
	void fK32EnumPageFilesW() { PA = kernel32.oK32EnumPageFilesW; runASM(); }
	void fK32EnumProcessModules() { PA = kernel32.oK32EnumProcessModules; runASM(); }
	void fK32EnumProcessModulesEx() { PA = kernel32.oK32EnumProcessModulesEx; runASM(); }
	void fK32EnumProcesses() { PA = kernel32.oK32EnumProcesses; runASM(); }
	void fK32GetDeviceDriverBaseNameA() { PA = kernel32.oK32GetDeviceDriverBaseNameA; runASM(); }
	void fK32GetDeviceDriverBaseNameW() { PA = kernel32.oK32GetDeviceDriverBaseNameW; runASM(); }
	void fK32GetDeviceDriverFileNameA() { PA = kernel32.oK32GetDeviceDriverFileNameA; runASM(); }
	void fK32GetDeviceDriverFileNameW() { PA = kernel32.oK32GetDeviceDriverFileNameW; runASM(); }
	void fK32GetMappedFileNameA() { PA = kernel32.oK32GetMappedFileNameA; runASM(); }
	void fK32GetMappedFileNameW() { PA = kernel32.oK32GetMappedFileNameW; runASM(); }
	void fK32GetModuleBaseNameA() { PA = kernel32.oK32GetModuleBaseNameA; runASM(); }
	void fK32GetModuleBaseNameW() { PA = kernel32.oK32GetModuleBaseNameW; runASM(); }
	void fK32GetModuleFileNameExA() { PA = kernel32.oK32GetModuleFileNameExA; runASM(); }
	void fK32GetModuleFileNameExW() { PA = kernel32.oK32GetModuleFileNameExW; runASM(); }
	void fK32GetModuleInformation() { PA = kernel32.oK32GetModuleInformation; runASM(); }
	void fK32GetPerformanceInfo() { PA = kernel32.oK32GetPerformanceInfo; runASM(); }
	void fK32GetProcessImageFileNameA() { PA = kernel32.oK32GetProcessImageFileNameA; runASM(); }
	void fK32GetProcessImageFileNameW() { PA = kernel32.oK32GetProcessImageFileNameW; runASM(); }
	void fK32GetProcessMemoryInfo() { PA = kernel32.oK32GetProcessMemoryInfo; runASM(); }
	void fK32GetWsChanges() { PA = kernel32.oK32GetWsChanges; runASM(); }
	void fK32GetWsChangesEx() { PA = kernel32.oK32GetWsChangesEx; runASM(); }
	void fK32InitializeProcessForWsWatch() { PA = kernel32.oK32InitializeProcessForWsWatch; runASM(); }
	void fK32QueryWorkingSet() { PA = kernel32.oK32QueryWorkingSet; runASM(); }
	void fK32QueryWorkingSetEx() { PA = kernel32.oK32QueryWorkingSetEx; runASM(); }
	void fLCIDToLocaleName() { PA = kernel32.oLCIDToLocaleName; runASM(); }
	void fLCMapStringA() { PA = kernel32.oLCMapStringA; runASM(); }
	void fLCMapStringEx() { PA = kernel32.oLCMapStringEx; runASM(); }
	void fLCMapStringW() { PA = kernel32.oLCMapStringW; runASM(); }
	void fLZClose() { PA = kernel32.oLZClose; runASM(); }
	void fLZCloseFile() { PA = kernel32.oLZCloseFile; runASM(); }
	void fLZCopy() { PA = kernel32.oLZCopy; runASM(); }
	void fLZCreateFileW() { PA = kernel32.oLZCreateFileW; runASM(); }
	void fLZDone() { PA = kernel32.oLZDone; runASM(); }
	void fLZInit() { PA = kernel32.oLZInit; runASM(); }
	void fLZOpenFileA() { PA = kernel32.oLZOpenFileA; runASM(); }
	void fLZOpenFileW() { PA = kernel32.oLZOpenFileW; runASM(); }
	void fLZRead() { PA = kernel32.oLZRead; runASM(); }
	void fLZSeek() { PA = kernel32.oLZSeek; runASM(); }
	void fLZStart() { PA = kernel32.oLZStart; runASM(); }
	void fLeaveCriticalSection() { PA = kernel32.oLeaveCriticalSection; runASM(); }
	void fLeaveCriticalSectionWhenCallbackReturns() { PA = kernel32.oLeaveCriticalSectionWhenCallbackReturns; runASM(); }
	void fLoadAppInitDlls() { PA = kernel32.oLoadAppInitDlls; runASM(); }
	void fLoadEnclaveData() { PA = kernel32.oLoadEnclaveData; runASM(); }
	void fLoadLibraryA() { PA = kernel32.oLoadLibraryA; runASM(); }
	void fLoadLibraryExA() { PA = kernel32.oLoadLibraryExA; runASM(); }
	void fLoadLibraryExW() { PA = kernel32.oLoadLibraryExW; runASM(); }
	void fLoadLibraryW() { PA = kernel32.oLoadLibraryW; runASM(); }
	void fLoadModule() { PA = kernel32.oLoadModule; runASM(); }
	//void fLoadPackagedLibrary() { PA = kernel32.oLoadPackagedLibrary; runASM(); }
	HMODULE WINAPI fLoadPackagedLibrary(LPCWSTR lpwLibFileName, DWORD Reserved) { return LoadLibraryExW(lpwLibFileName, NULL, NULL); }
	void fLoadResource() { PA = kernel32.oLoadResource; runASM(); }
	void fLoadStringBaseExW() { PA = kernel32.oLoadStringBaseExW; runASM(); }
	void fLoadStringBaseW() { PA = kernel32.oLoadStringBaseW; runASM(); }
	void fLocalAlloc() { PA = kernel32.oLocalAlloc; runASM(); }
	void fLocalCompact() { PA = kernel32.oLocalCompact; runASM(); }
	void fLocalFileTimeToFileTime() { PA = kernel32.oLocalFileTimeToFileTime; runASM(); }
	void fLocalFileTimeToLocalSystemTime() { PA = kernel32.oLocalFileTimeToLocalSystemTime; runASM(); }
	void fLocalFlags() { PA = kernel32.oLocalFlags; runASM(); }
	void fLocalFree() { PA = kernel32.oLocalFree; runASM(); }
	void fLocalHandle() { PA = kernel32.oLocalHandle; runASM(); }
	void fLocalLock() { PA = kernel32.oLocalLock; runASM(); }
	void fLocalReAlloc() { PA = kernel32.oLocalReAlloc; runASM(); }
	void fLocalShrink() { PA = kernel32.oLocalShrink; runASM(); }
	void fLocalSize() { PA = kernel32.oLocalSize; runASM(); }
	void fLocalSystemTimeToLocalFileTime() { PA = kernel32.oLocalSystemTimeToLocalFileTime; runASM(); }
	void fLocalUnlock() { PA = kernel32.oLocalUnlock; runASM(); }
	void fLocaleNameToLCID() { PA = kernel32.oLocaleNameToLCID; runASM(); }
	void fLocateXStateFeature() { PA = kernel32.oLocateXStateFeature; runASM(); }
	void fLockFile() { PA = kernel32.oLockFile; runASM(); }
	void fLockFileEx() { PA = kernel32.oLockFileEx; runASM(); }
	void fLockResource() { PA = kernel32.oLockResource; runASM(); }
	void fMapUserPhysicalPages() { PA = kernel32.oMapUserPhysicalPages; runASM(); }
	void fMapUserPhysicalPagesScatter() { PA = kernel32.oMapUserPhysicalPagesScatter; runASM(); }
	void fMapViewOfFile() { PA = kernel32.oMapViewOfFile; runASM(); }
	void fMapViewOfFileEx() { PA = kernel32.oMapViewOfFileEx; runASM(); }
	void fMapViewOfFileExNuma() { PA = kernel32.oMapViewOfFileExNuma; runASM(); }
	void fMapViewOfFileFromApp() { PA = kernel32.oMapViewOfFileFromApp; runASM(); }
	void fModule32First() { PA = kernel32.oModule32First; runASM(); }
	void fModule32FirstW() { PA = kernel32.oModule32FirstW; runASM(); }
	void fModule32Next() { PA = kernel32.oModule32Next; runASM(); }
	void fModule32NextW() { PA = kernel32.oModule32NextW; runASM(); }
	void fMoveFileA() { PA = kernel32.oMoveFileA; runASM(); }
	void fMoveFileExA() { PA = kernel32.oMoveFileExA; runASM(); }
	void fMoveFileExW() { PA = kernel32.oMoveFileExW; runASM(); }
	void fMoveFileTransactedA() { PA = kernel32.oMoveFileTransactedA; runASM(); }
	void fMoveFileTransactedW() { PA = kernel32.oMoveFileTransactedW; runASM(); }
	void fMoveFileW() { PA = kernel32.oMoveFileW; runASM(); }
	void fMoveFileWithProgressA() { PA = kernel32.oMoveFileWithProgressA; runASM(); }
	void fMoveFileWithProgressW() { PA = kernel32.oMoveFileWithProgressW; runASM(); }
	void fMulDiv() { PA = kernel32.oMulDiv; runASM(); }
	void fMultiByteToWideChar() { PA = kernel32.oMultiByteToWideChar; runASM(); }
	void fNeedCurrentDirectoryForExePathA() { PA = kernel32.oNeedCurrentDirectoryForExePathA; runASM(); }
	void fNeedCurrentDirectoryForExePathW() { PA = kernel32.oNeedCurrentDirectoryForExePathW; runASM(); }
	void fNlsCheckPolicy() { PA = kernel32.oNlsCheckPolicy; runASM(); }
	void fNlsEventDataDescCreate() { PA = kernel32.oNlsEventDataDescCreate; runASM(); }
	void fNlsGetCacheUpdateCount() { PA = kernel32.oNlsGetCacheUpdateCount; runASM(); }
	void fNlsUpdateLocale() { PA = kernel32.oNlsUpdateLocale; runASM(); }
	void fNlsUpdateSystemLocale() { PA = kernel32.oNlsUpdateSystemLocale; runASM(); }
	void fNlsWriteEtwEvent() { PA = kernel32.oNlsWriteEtwEvent; runASM(); }
	void fNormalizeString() { PA = kernel32.oNormalizeString; runASM(); }
	void fNotifyMountMgr() { PA = kernel32.oNotifyMountMgr; runASM(); }
	void fNotifyUILanguageChange() { PA = kernel32.oNotifyUILanguageChange; runASM(); }
	void fNtVdm64CreateProcessInternalW() { PA = kernel32.oNtVdm64CreateProcessInternalW; runASM(); }
	void fOOBEComplete() { PA = kernel32.oOOBEComplete; runASM(); }
	void fOfferVirtualMemory() { PA = kernel32.oOfferVirtualMemory; runASM(); }
	void fOpenConsoleW() { PA = kernel32.oOpenConsoleW; runASM(); }
	void fOpenConsoleWStub() { PA = kernel32.oOpenConsoleWStub; runASM(); }
	void fOpenEventA() { PA = kernel32.oOpenEventA; runASM(); }
	void fOpenEventW() { PA = kernel32.oOpenEventW; runASM(); }
	void fOpenFile() { PA = kernel32.oOpenFile; runASM(); }
	void fOpenFileById() { PA = kernel32.oOpenFileById; runASM(); }
	void fOpenFileMappingA() { PA = kernel32.oOpenFileMappingA; runASM(); }
	void fOpenFileMappingW() { PA = kernel32.oOpenFileMappingW; runASM(); }
	void fOpenJobObjectA() { PA = kernel32.oOpenJobObjectA; runASM(); }
	void fOpenJobObjectW() { PA = kernel32.oOpenJobObjectW; runASM(); }
	void fOpenMutexA() { PA = kernel32.oOpenMutexA; runASM(); }
	void fOpenMutexW() { PA = kernel32.oOpenMutexW; runASM(); }
	void fOpenPackageInfoByFullName() { PA = kernel32.oOpenPackageInfoByFullName; runASM(); }
	void fOpenPrivateNamespaceA() { PA = kernel32.oOpenPrivateNamespaceA; runASM(); }
	void fOpenPrivateNamespaceW() { PA = kernel32.oOpenPrivateNamespaceW; runASM(); }
	void fOpenProcess() { PA = kernel32.oOpenProcess; runASM(); }
	void fOpenProcessToken() { PA = kernel32.oOpenProcessToken; runASM(); }
	void fOpenProfileUserMapping() { PA = kernel32.oOpenProfileUserMapping; runASM(); }
	void fOpenSemaphoreA() { PA = kernel32.oOpenSemaphoreA; runASM(); }
	void fOpenSemaphoreW() { PA = kernel32.oOpenSemaphoreW; runASM(); }
	void fOpenState() { PA = kernel32.oOpenState; runASM(); }
	void fOpenStateExplicit() { PA = kernel32.oOpenStateExplicit; runASM(); }
	void fOpenThread() { PA = kernel32.oOpenThread; runASM(); }
	void fOpenThreadToken() { PA = kernel32.oOpenThreadToken; runASM(); }
	void fOpenWaitableTimerA() { PA = kernel32.oOpenWaitableTimerA; runASM(); }
	void fOpenWaitableTimerW() { PA = kernel32.oOpenWaitableTimerW; runASM(); }
	void fOutputDebugStringA() { PA = kernel32.oOutputDebugStringA; runASM(); }
	void fOutputDebugStringW() { PA = kernel32.oOutputDebugStringW; runASM(); }
	void fPackageFamilyNameFromFullName() { PA = kernel32.oPackageFamilyNameFromFullName; runASM(); }
	void fPackageFamilyNameFromId() { PA = kernel32.oPackageFamilyNameFromId; runASM(); }
	void fPackageFullNameFromId() { PA = kernel32.oPackageFullNameFromId; runASM(); }
	void fPackageIdFromFullName() { PA = kernel32.oPackageIdFromFullName; runASM(); }
	void fPackageNameAndPublisherIdFromFamilyName() { PA = kernel32.oPackageNameAndPublisherIdFromFamilyName; runASM(); }
	void fParseApplicationUserModelId() { PA = kernel32.oParseApplicationUserModelId; runASM(); }
	void fPeekConsoleInputA() { PA = kernel32.oPeekConsoleInputA; runASM(); }
	void fPeekConsoleInputW() { PA = kernel32.oPeekConsoleInputW; runASM(); }
	void fPeekNamedPipe() { PA = kernel32.oPeekNamedPipe; runASM(); }
	void fPostQueuedCompletionStatus() { PA = kernel32.oPostQueuedCompletionStatus; runASM(); }
	void fPowerClearRequest() { PA = kernel32.oPowerClearRequest; runASM(); }
	void fPowerCreateRequest() { PA = kernel32.oPowerCreateRequest; runASM(); }
	void fPowerSetRequest() { PA = kernel32.oPowerSetRequest; runASM(); }
	void fPrefetchVirtualMemory() { PA = kernel32.oPrefetchVirtualMemory; runASM(); }
	void fPrepareTape() { PA = kernel32.oPrepareTape; runASM(); }
	void fPrivCopyFileExW() { PA = kernel32.oPrivCopyFileExW; runASM(); }
	void fPrivMoveFileIdentityW() { PA = kernel32.oPrivMoveFileIdentityW; runASM(); }
	void fProcess32First() { PA = kernel32.oProcess32First; runASM(); }
	void fProcess32FirstW() { PA = kernel32.oProcess32FirstW; runASM(); }
	void fProcess32Next() { PA = kernel32.oProcess32Next; runASM(); }
	void fProcess32NextW() { PA = kernel32.oProcess32NextW; runASM(); }
	void fProcessIdToSessionId() { PA = kernel32.oProcessIdToSessionId; runASM(); }
	void fPssCaptureSnapshot() { PA = kernel32.oPssCaptureSnapshot; runASM(); }
	void fPssDuplicateSnapshot() { PA = kernel32.oPssDuplicateSnapshot; runASM(); }
	void fPssFreeSnapshot() { PA = kernel32.oPssFreeSnapshot; runASM(); }
	void fPssQuerySnapshot() { PA = kernel32.oPssQuerySnapshot; runASM(); }
	void fPssWalkMarkerCreate() { PA = kernel32.oPssWalkMarkerCreate; runASM(); }
	void fPssWalkMarkerFree() { PA = kernel32.oPssWalkMarkerFree; runASM(); }
	void fPssWalkMarkerGetPosition() { PA = kernel32.oPssWalkMarkerGetPosition; runASM(); }
	void fPssWalkMarkerRewind() { PA = kernel32.oPssWalkMarkerRewind; runASM(); }
	void fPssWalkMarkerSeek() { PA = kernel32.oPssWalkMarkerSeek; runASM(); }
	void fPssWalkMarkerSeekToBeginning() { PA = kernel32.oPssWalkMarkerSeekToBeginning; runASM(); }
	void fPssWalkMarkerSetPosition() { PA = kernel32.oPssWalkMarkerSetPosition; runASM(); }
	void fPssWalkMarkerTell() { PA = kernel32.oPssWalkMarkerTell; runASM(); }
	void fPssWalkSnapshot() { PA = kernel32.oPssWalkSnapshot; runASM(); }
	void fPulseEvent() { PA = kernel32.oPulseEvent; runASM(); }
	void fPurgeComm() { PA = kernel32.oPurgeComm; runASM(); }
	void fQueryActCtxSettingsW() { PA = kernel32.oQueryActCtxSettingsW; runASM(); }
	void fQueryActCtxSettingsWWorker() { PA = kernel32.oQueryActCtxSettingsWWorker; runASM(); }
	void fQueryActCtxW() { PA = kernel32.oQueryActCtxW; runASM(); }
	void fQueryActCtxWWorker() { PA = kernel32.oQueryActCtxWWorker; runASM(); }
	void fQueryDepthSList() { PA = kernel32.oQueryDepthSList; runASM(); }
	void fQueryDosDeviceA() { PA = kernel32.oQueryDosDeviceA; runASM(); }
	void fQueryDosDeviceW() { PA = kernel32.oQueryDosDeviceW; runASM(); }
	void fQueryFullProcessImageNameA() { PA = kernel32.oQueryFullProcessImageNameA; runASM(); }
	void fQueryFullProcessImageNameW() { PA = kernel32.oQueryFullProcessImageNameW; runASM(); }
	void fQueryIdleProcessorCycleTime() { PA = kernel32.oQueryIdleProcessorCycleTime; runASM(); }
	void fQueryIdleProcessorCycleTimeEx() { PA = kernel32.oQueryIdleProcessorCycleTimeEx; runASM(); }
	void fQueryInformationJobObject() { PA = kernel32.oQueryInformationJobObject; runASM(); }
	void fQueryIoRateControlInformationJobObject() { PA = kernel32.oQueryIoRateControlInformationJobObject; runASM(); }
	void fQueryMemoryResourceNotification() { PA = kernel32.oQueryMemoryResourceNotification; runASM(); }
	void fQueryPerformanceCounter() { PA = kernel32.oQueryPerformanceCounter; runASM(); }
	void fQueryPerformanceFrequency() { PA = kernel32.oQueryPerformanceFrequency; runASM(); }
	void fQueryProcessAffinityUpdateMode() { PA = kernel32.oQueryProcessAffinityUpdateMode; runASM(); }
	void fQueryProcessCycleTime() { PA = kernel32.oQueryProcessCycleTime; runASM(); }
	void fQueryProtectedPolicy() { PA = kernel32.oQueryProtectedPolicy; runASM(); }
	void fQueryThreadCycleTime() { PA = kernel32.oQueryThreadCycleTime; runASM(); }
	void fQueryThreadProfiling() { PA = kernel32.oQueryThreadProfiling; runASM(); }
	void fQueryThreadpoolStackInformation() { PA = kernel32.oQueryThreadpoolStackInformation; runASM(); }
	void fQueryUmsThreadInformation() { PA = kernel32.oQueryUmsThreadInformation; runASM(); }
	void fQueryUnbiasedInterruptTime() { PA = kernel32.oQueryUnbiasedInterruptTime; runASM(); }
	void fQueueUserAPC() { PA = kernel32.oQueueUserAPC; runASM(); }
	void fQueueUserWorkItem() { PA = kernel32.oQueueUserWorkItem; runASM(); }
	void fQuirkGetData2Worker() { PA = kernel32.oQuirkGetData2Worker; runASM(); }
	void fQuirkGetDataWorker() { PA = kernel32.oQuirkGetDataWorker; runASM(); }
	void fQuirkIsEnabled2Worker() { PA = kernel32.oQuirkIsEnabled2Worker; runASM(); }
	void fQuirkIsEnabled3Worker() { PA = kernel32.oQuirkIsEnabled3Worker; runASM(); }
	void fQuirkIsEnabledForPackage2Worker() { PA = kernel32.oQuirkIsEnabledForPackage2Worker; runASM(); }
	void fQuirkIsEnabledForPackage3Worker() { PA = kernel32.oQuirkIsEnabledForPackage3Worker; runASM(); }
	void fQuirkIsEnabledForPackage4Worker() { PA = kernel32.oQuirkIsEnabledForPackage4Worker; runASM(); }
	void fQuirkIsEnabledForPackageWorker() { PA = kernel32.oQuirkIsEnabledForPackageWorker; runASM(); }
	void fQuirkIsEnabledForProcessWorker() { PA = kernel32.oQuirkIsEnabledForProcessWorker; runASM(); }
	void fQuirkIsEnabledWorker() { PA = kernel32.oQuirkIsEnabledWorker; runASM(); }
	void fRaiseException() { PA = kernel32.oRaiseException; runASM(); }
	void fRaiseFailFastException() { PA = kernel32.oRaiseFailFastException; runASM(); }
	void fRaiseInvalid16BitExeError() { PA = kernel32.oRaiseInvalid16BitExeError; runASM(); }
	void fReOpenFile() { PA = kernel32.oReOpenFile; runASM(); }
	void fReadConsoleA() { PA = kernel32.oReadConsoleA; runASM(); }
	void fReadConsoleInputA() { PA = kernel32.oReadConsoleInputA; runASM(); }
	void fReadConsoleInputExA() { PA = kernel32.oReadConsoleInputExA; runASM(); }
	void fReadConsoleInputExW() { PA = kernel32.oReadConsoleInputExW; runASM(); }
	void fReadConsoleInputW() { PA = kernel32.oReadConsoleInputW; runASM(); }
	void fReadConsoleOutputA() { PA = kernel32.oReadConsoleOutputA; runASM(); }
	void fReadConsoleOutputAttribute() { PA = kernel32.oReadConsoleOutputAttribute; runASM(); }
	void fReadConsoleOutputCharacterA() { PA = kernel32.oReadConsoleOutputCharacterA; runASM(); }
	void fReadConsoleOutputCharacterW() { PA = kernel32.oReadConsoleOutputCharacterW; runASM(); }
	void fReadConsoleOutputW() { PA = kernel32.oReadConsoleOutputW; runASM(); }
	void fReadConsoleW() { PA = kernel32.oReadConsoleW; runASM(); }
	void fReadDirectoryChangesExW() { PA = kernel32.oReadDirectoryChangesExW; runASM(); }
	void fReadDirectoryChangesW() { PA = kernel32.oReadDirectoryChangesW; runASM(); }
	void fReadFile() { PA = kernel32.oReadFile; runASM(); }
	void fReadFileEx() { PA = kernel32.oReadFileEx; runASM(); }
	void fReadFileScatter() { PA = kernel32.oReadFileScatter; runASM(); }
	void fReadProcessMemory() { PA = kernel32.oReadProcessMemory; runASM(); }
	void fReadThreadProfilingData() { PA = kernel32.oReadThreadProfilingData; runASM(); }
	void fReclaimVirtualMemory() { PA = kernel32.oReclaimVirtualMemory; runASM(); }
	void fRegCloseKey() { PA = kernel32.oRegCloseKey; runASM(); }
	void fRegCopyTreeW() { PA = kernel32.oRegCopyTreeW; runASM(); }
	void fRegCreateKeyExA() { PA = kernel32.oRegCreateKeyExA; runASM(); }
	void fRegCreateKeyExW() { PA = kernel32.oRegCreateKeyExW; runASM(); }
	void fRegDeleteKeyExA() { PA = kernel32.oRegDeleteKeyExA; runASM(); }
	void fRegDeleteKeyExW() { PA = kernel32.oRegDeleteKeyExW; runASM(); }
	void fRegDeleteTreeA() { PA = kernel32.oRegDeleteTreeA; runASM(); }
	void fRegDeleteTreeW() { PA = kernel32.oRegDeleteTreeW; runASM(); }
	void fRegDeleteValueA() { PA = kernel32.oRegDeleteValueA; runASM(); }
	void fRegDeleteValueW() { PA = kernel32.oRegDeleteValueW; runASM(); }
	void fRegDisablePredefinedCacheEx() { PA = kernel32.oRegDisablePredefinedCacheEx; runASM(); }
	void fRegEnumKeyExA() { PA = kernel32.oRegEnumKeyExA; runASM(); }
	void fRegEnumKeyExW() { PA = kernel32.oRegEnumKeyExW; runASM(); }
	void fRegEnumValueA() { PA = kernel32.oRegEnumValueA; runASM(); }
	void fRegEnumValueW() { PA = kernel32.oRegEnumValueW; runASM(); }
	void fRegFlushKey() { PA = kernel32.oRegFlushKey; runASM(); }
	void fRegGetKeySecurity() { PA = kernel32.oRegGetKeySecurity; runASM(); }
	void fRegGetValueA() { PA = kernel32.oRegGetValueA; runASM(); }
	void fRegGetValueW() { PA = kernel32.oRegGetValueW; runASM(); }
	void fRegLoadKeyA() { PA = kernel32.oRegLoadKeyA; runASM(); }
	void fRegLoadKeyW() { PA = kernel32.oRegLoadKeyW; runASM(); }
	void fRegLoadMUIStringA() { PA = kernel32.oRegLoadMUIStringA; runASM(); }
	void fRegLoadMUIStringW() { PA = kernel32.oRegLoadMUIStringW; runASM(); }
	void fRegNotifyChangeKeyValue() { PA = kernel32.oRegNotifyChangeKeyValue; runASM(); }
	void fRegOpenCurrentUser() { PA = kernel32.oRegOpenCurrentUser; runASM(); }
	void fRegOpenKeyExA() { PA = kernel32.oRegOpenKeyExA; runASM(); }
	void fRegOpenKeyExW() { PA = kernel32.oRegOpenKeyExW; runASM(); }
	void fRegOpenUserClassesRoot() { PA = kernel32.oRegOpenUserClassesRoot; runASM(); }
	void fRegQueryInfoKeyA() { PA = kernel32.oRegQueryInfoKeyA; runASM(); }
	void fRegQueryInfoKeyW() { PA = kernel32.oRegQueryInfoKeyW; runASM(); }
	void fRegQueryValueExA() { PA = kernel32.oRegQueryValueExA; runASM(); }
	void fRegQueryValueExW() { PA = kernel32.oRegQueryValueExW; runASM(); }
	void fRegRestoreKeyA() { PA = kernel32.oRegRestoreKeyA; runASM(); }
	void fRegRestoreKeyW() { PA = kernel32.oRegRestoreKeyW; runASM(); }
	void fRegSaveKeyExA() { PA = kernel32.oRegSaveKeyExA; runASM(); }
	void fRegSaveKeyExW() { PA = kernel32.oRegSaveKeyExW; runASM(); }
	void fRegSetKeySecurity() { PA = kernel32.oRegSetKeySecurity; runASM(); }
	void fRegSetValueExA() { PA = kernel32.oRegSetValueExA; runASM(); }
	void fRegSetValueExW() { PA = kernel32.oRegSetValueExW; runASM(); }
	void fRegUnLoadKeyA() { PA = kernel32.oRegUnLoadKeyA; runASM(); }
	void fRegUnLoadKeyW() { PA = kernel32.oRegUnLoadKeyW; runASM(); }
	void fRegisterApplicationRecoveryCallback() { PA = kernel32.oRegisterApplicationRecoveryCallback; runASM(); }
	void fRegisterApplicationRestart() { PA = kernel32.oRegisterApplicationRestart; runASM(); }
	void fRegisterBadMemoryNotification() { PA = kernel32.oRegisterBadMemoryNotification; runASM(); }
	void fRegisterConsoleIME() { PA = kernel32.oRegisterConsoleIME; runASM(); }
	void fRegisterConsoleOS2() { PA = kernel32.oRegisterConsoleOS2; runASM(); }
	void fRegisterConsoleVDM() { PA = kernel32.oRegisterConsoleVDM; runASM(); }
	void fRegisterWaitForInputIdle() { PA = kernel32.oRegisterWaitForInputIdle; runASM(); }
	void fRegisterWaitForSingleObject() { PA = kernel32.oRegisterWaitForSingleObject; runASM(); }
	void fRegisterWaitForSingleObjectEx() { PA = kernel32.oRegisterWaitForSingleObjectEx; runASM(); }
	void fRegisterWaitUntilOOBECompleted() { PA = kernel32.oRegisterWaitUntilOOBECompleted; runASM(); }
	void fRegisterWowBaseHandlers() { PA = kernel32.oRegisterWowBaseHandlers; runASM(); }
	void fRegisterWowExec() { PA = kernel32.oRegisterWowExec; runASM(); }
	void fReleaseActCtx() { PA = kernel32.oReleaseActCtx; runASM(); }
	void fReleaseActCtxWorker() { PA = kernel32.oReleaseActCtxWorker; runASM(); }
	void fReleaseMutex() { PA = kernel32.oReleaseMutex; runASM(); }
	void fReleaseMutexWhenCallbackReturns() { PA = kernel32.oReleaseMutexWhenCallbackReturns; runASM(); }
	void fReleaseSRWLockExclusive() { PA = kernel32.oReleaseSRWLockExclusive; runASM(); }
	void fReleaseSRWLockShared() { PA = kernel32.oReleaseSRWLockShared; runASM(); }
	void fReleaseSemaphore() { PA = kernel32.oReleaseSemaphore; runASM(); }
	void fReleaseSemaphoreWhenCallbackReturns() { PA = kernel32.oReleaseSemaphoreWhenCallbackReturns; runASM(); }
	void fRemoveDirectoryA() { PA = kernel32.oRemoveDirectoryA; runASM(); }
	void fRemoveDirectoryTransactedA() { PA = kernel32.oRemoveDirectoryTransactedA; runASM(); }
	void fRemoveDirectoryTransactedW() { PA = kernel32.oRemoveDirectoryTransactedW; runASM(); }
	void fRemoveDirectoryW() { PA = kernel32.oRemoveDirectoryW; runASM(); }
	void fRemoveDllDirectory() { PA = kernel32.oRemoveDllDirectory; runASM(); }
	void fRemoveLocalAlternateComputerNameA() { PA = kernel32.oRemoveLocalAlternateComputerNameA; runASM(); }
	void fRemoveLocalAlternateComputerNameW() { PA = kernel32.oRemoveLocalAlternateComputerNameW; runASM(); }
	void fRemoveSecureMemoryCacheCallback() { PA = kernel32.oRemoveSecureMemoryCacheCallback; runASM(); }
	void fRemoveVectoredContinueHandler() { PA = kernel32.oRemoveVectoredContinueHandler; runASM(); }
	void fRemoveVectoredExceptionHandler() { PA = kernel32.oRemoveVectoredExceptionHandler; runASM(); }
	void fReplaceFile() { PA = kernel32.oReplaceFile; runASM(); }
	void fReplaceFileA() { PA = kernel32.oReplaceFileA; runASM(); }
	void fReplaceFileW() { PA = kernel32.oReplaceFileW; runASM(); }
	void fReplacePartitionUnit() { PA = kernel32.oReplacePartitionUnit; runASM(); }
	void fRequestDeviceWakeup() { PA = kernel32.oRequestDeviceWakeup; runASM(); }
	void fRequestWakeupLatency() { PA = kernel32.oRequestWakeupLatency; runASM(); }
	void fResetEvent() { PA = kernel32.oResetEvent; runASM(); }
	void fResetWriteWatch() { PA = kernel32.oResetWriteWatch; runASM(); }
	void fResizePseudoConsole() { PA = kernel32.oResizePseudoConsole; runASM(); }
	void fResolveDelayLoadedAPI() { PA = kernel32.oResolveDelayLoadedAPI; runASM(); }
	void fResolveDelayLoadsFromDll() { PA = kernel32.oResolveDelayLoadsFromDll; runASM(); }
	void fResolveLocaleName() { PA = kernel32.oResolveLocaleName; runASM(); }
	void fRestoreLastError() { PA = kernel32.oRestoreLastError; runASM(); }
	void fResumeThread() { PA = kernel32.oResumeThread; runASM(); }
	void fRtlAddFunctionTable() { PA = kernel32.oRtlAddFunctionTable; runASM(); }
	void fRtlCaptureContext() { PA = kernel32.oRtlCaptureContext; runASM(); }
	void fRtlCaptureStackBackTrace() { PA = kernel32.oRtlCaptureStackBackTrace; runASM(); }
	void fRtlCompareMemory() { PA = kernel32.oRtlCompareMemory; runASM(); }
	void fRtlCopyMemory() { PA = kernel32.oRtlCopyMemory; runASM(); }
	void fRtlDeleteFunctionTable() { PA = kernel32.oRtlDeleteFunctionTable; runASM(); }
	void fRtlFillMemory() { PA = kernel32.oRtlFillMemory; runASM(); }
	void fRtlInstallFunctionTableCallback() { PA = kernel32.oRtlInstallFunctionTableCallback; runASM(); }
	void fRtlLookupFunctionEntry() { PA = kernel32.oRtlLookupFunctionEntry; runASM(); }
	void fRtlMoveMemory() { PA = kernel32.oRtlMoveMemory; runASM(); }
	void fRtlPcToFileHeader() { PA = kernel32.oRtlPcToFileHeader; runASM(); }
	void fRtlRaiseException() { PA = kernel32.oRtlRaiseException; runASM(); }
	void fRtlRestoreContext() { PA = kernel32.oRtlRestoreContext; runASM(); }
	void fRtlUnwind() { PA = kernel32.oRtlUnwind; runASM(); }
	void fRtlUnwindEx() { PA = kernel32.oRtlUnwindEx; runASM(); }
	void fRtlVirtualUnwind() { PA = kernel32.oRtlVirtualUnwind; runASM(); }
	void fRtlZeroMemory() { PA = kernel32.oRtlZeroMemory; runASM(); }
	void fScrollConsoleScreenBufferA() { PA = kernel32.oScrollConsoleScreenBufferA; runASM(); }
	void fScrollConsoleScreenBufferW() { PA = kernel32.oScrollConsoleScreenBufferW; runASM(); }
	void fSearchPathA() { PA = kernel32.oSearchPathA; runASM(); }
	void fSearchPathW() { PA = kernel32.oSearchPathW; runASM(); }
	void fSetCachedSigningLevel() { PA = kernel32.oSetCachedSigningLevel; runASM(); }
	void fSetCalendarInfoA() { PA = kernel32.oSetCalendarInfoA; runASM(); }
	void fSetCalendarInfoW() { PA = kernel32.oSetCalendarInfoW; runASM(); }
	void fSetComPlusPackageInstallStatus() { PA = kernel32.oSetComPlusPackageInstallStatus; runASM(); }
	void fSetCommBreak() { PA = kernel32.oSetCommBreak; runASM(); }
	void fSetCommConfig() { PA = kernel32.oSetCommConfig; runASM(); }
	void fSetCommMask() { PA = kernel32.oSetCommMask; runASM(); }
	void fSetCommState() { PA = kernel32.oSetCommState; runASM(); }
	void fSetCommTimeouts() { PA = kernel32.oSetCommTimeouts; runASM(); }
	void fSetComputerNameA() { PA = kernel32.oSetComputerNameA; runASM(); }
	void fSetComputerNameEx2W() { PA = kernel32.oSetComputerNameEx2W; runASM(); }
	void fSetComputerNameExA() { PA = kernel32.oSetComputerNameExA; runASM(); }
	void fSetComputerNameExW() { PA = kernel32.oSetComputerNameExW; runASM(); }
	void fSetComputerNameW() { PA = kernel32.oSetComputerNameW; runASM(); }
	void fSetConsoleActiveScreenBuffer() { PA = kernel32.oSetConsoleActiveScreenBuffer; runASM(); }
	void fSetConsoleCP() { PA = kernel32.oSetConsoleCP; runASM(); }
	void fSetConsoleCtrlHandler() { PA = kernel32.oSetConsoleCtrlHandler; runASM(); }
	void fSetConsoleCursor() { PA = kernel32.oSetConsoleCursor; runASM(); }
	void fSetConsoleCursorInfo() { PA = kernel32.oSetConsoleCursorInfo; runASM(); }
	void fSetConsoleCursorMode() { PA = kernel32.oSetConsoleCursorMode; runASM(); }
	void fSetConsoleCursorPosition() { PA = kernel32.oSetConsoleCursorPosition; runASM(); }
	void fSetConsoleDisplayMode() { PA = kernel32.oSetConsoleDisplayMode; runASM(); }
	void fSetConsoleFont() { PA = kernel32.oSetConsoleFont; runASM(); }
	void fSetConsoleHardwareState() { PA = kernel32.oSetConsoleHardwareState; runASM(); }
	void fSetConsoleHistoryInfo() { PA = kernel32.oSetConsoleHistoryInfo; runASM(); }
	void fSetConsoleIcon() { PA = kernel32.oSetConsoleIcon; runASM(); }
	void fSetConsoleInputExeNameA() { PA = kernel32.oSetConsoleInputExeNameA; runASM(); }
	void fSetConsoleInputExeNameW() { PA = kernel32.oSetConsoleInputExeNameW; runASM(); }
	void fSetConsoleKeyShortcuts() { PA = kernel32.oSetConsoleKeyShortcuts; runASM(); }
	void fSetConsoleLocalEUDC() { PA = kernel32.oSetConsoleLocalEUDC; runASM(); }
	void fSetConsoleMaximumWindowSize() { PA = kernel32.oSetConsoleMaximumWindowSize; runASM(); }
	void fSetConsoleMenuClose() { PA = kernel32.oSetConsoleMenuClose; runASM(); }
	void fSetConsoleMode() { PA = kernel32.oSetConsoleMode; runASM(); }
	void fSetConsoleNlsMode() { PA = kernel32.oSetConsoleNlsMode; runASM(); }
	void fSetConsoleNumberOfCommandsA() { PA = kernel32.oSetConsoleNumberOfCommandsA; runASM(); }
	void fSetConsoleNumberOfCommandsW() { PA = kernel32.oSetConsoleNumberOfCommandsW; runASM(); }
	void fSetConsoleOS2OemFormat() { PA = kernel32.oSetConsoleOS2OemFormat; runASM(); }
	void fSetConsoleOutputCP() { PA = kernel32.oSetConsoleOutputCP; runASM(); }
	void fSetConsolePalette() { PA = kernel32.oSetConsolePalette; runASM(); }
	void fSetConsoleScreenBufferInfoEx() { PA = kernel32.oSetConsoleScreenBufferInfoEx; runASM(); }
	void fSetConsoleScreenBufferSize() { PA = kernel32.oSetConsoleScreenBufferSize; runASM(); }
	void fSetConsoleTextAttribute() { PA = kernel32.oSetConsoleTextAttribute; runASM(); }
	void fSetConsoleTitleA() { PA = kernel32.oSetConsoleTitleA; runASM(); }
	void fSetConsoleTitleW() { PA = kernel32.oSetConsoleTitleW; runASM(); }
	void fSetConsoleWindowInfo() { PA = kernel32.oSetConsoleWindowInfo; runASM(); }
	void fSetCriticalSectionSpinCount() { PA = kernel32.oSetCriticalSectionSpinCount; runASM(); }
	void fSetCurrentConsoleFontEx() { PA = kernel32.oSetCurrentConsoleFontEx; runASM(); }
	void fSetCurrentDirectoryA() { PA = kernel32.oSetCurrentDirectoryA; runASM(); }
	void fSetCurrentDirectoryW() { PA = kernel32.oSetCurrentDirectoryW; runASM(); }
	void fSetDefaultCommConfigA() { PA = kernel32.oSetDefaultCommConfigA; runASM(); }
	void fSetDefaultCommConfigW() { PA = kernel32.oSetDefaultCommConfigW; runASM(); }
	void fSetDefaultDllDirectories() { PA = kernel32.oSetDefaultDllDirectories; runASM(); }
	void fSetDllDirectoryA() { PA = kernel32.oSetDllDirectoryA; runASM(); }
	void fSetDllDirectoryW() { PA = kernel32.oSetDllDirectoryW; runASM(); }
	void fSetDynamicTimeZoneInformation() { PA = kernel32.oSetDynamicTimeZoneInformation; runASM(); }
	void fSetEndOfFile() { PA = kernel32.oSetEndOfFile; runASM(); }
	void fSetEnvironmentStringsA() { PA = kernel32.oSetEnvironmentStringsA; runASM(); }
	void fSetEnvironmentStringsW() { PA = kernel32.oSetEnvironmentStringsW; runASM(); }
	void fSetEnvironmentVariableA() { PA = kernel32.oSetEnvironmentVariableA; runASM(); }
	void fSetEnvironmentVariableW() { PA = kernel32.oSetEnvironmentVariableW; runASM(); }
	void fSetErrorMode() { PA = kernel32.oSetErrorMode; runASM(); }
	void fSetEvent() { PA = kernel32.oSetEvent; runASM(); }
	void fSetEventWhenCallbackReturns() { PA = kernel32.oSetEventWhenCallbackReturns; runASM(); }
	void fSetFileApisToANSI() { PA = kernel32.oSetFileApisToANSI; runASM(); }
	void fSetFileApisToOEM() { PA = kernel32.oSetFileApisToOEM; runASM(); }
	void fSetFileAttributesA() { PA = kernel32.oSetFileAttributesA; runASM(); }
	void fSetFileAttributesTransactedA() { PA = kernel32.oSetFileAttributesTransactedA; runASM(); }
	void fSetFileAttributesTransactedW() { PA = kernel32.oSetFileAttributesTransactedW; runASM(); }
	void fSetFileAttributesW() { PA = kernel32.oSetFileAttributesW; runASM(); }
	void fSetFileBandwidthReservation() { PA = kernel32.oSetFileBandwidthReservation; runASM(); }
	void fSetFileCompletionNotificationModes() { PA = kernel32.oSetFileCompletionNotificationModes; runASM(); }
	void fSetFileInformationByHandle() { PA = kernel32.oSetFileInformationByHandle; runASM(); }
	void fSetFileIoOverlappedRange() { PA = kernel32.oSetFileIoOverlappedRange; runASM(); }
	void fSetFilePointer() { PA = kernel32.oSetFilePointer; runASM(); }
	void fSetFilePointerEx() { PA = kernel32.oSetFilePointerEx; runASM(); }
	void fSetFileShortNameA() { PA = kernel32.oSetFileShortNameA; runASM(); }
	void fSetFileShortNameW() { PA = kernel32.oSetFileShortNameW; runASM(); }
	void fSetFileTime() { PA = kernel32.oSetFileTime; runASM(); }
	void fSetFileValidData() { PA = kernel32.oSetFileValidData; runASM(); }
	void fSetFirmwareEnvironmentVariableA() { PA = kernel32.oSetFirmwareEnvironmentVariableA; runASM(); }
	void fSetFirmwareEnvironmentVariableExA() { PA = kernel32.oSetFirmwareEnvironmentVariableExA; runASM(); }
	void fSetFirmwareEnvironmentVariableExW() { PA = kernel32.oSetFirmwareEnvironmentVariableExW; runASM(); }
	void fSetFirmwareEnvironmentVariableW() { PA = kernel32.oSetFirmwareEnvironmentVariableW; runASM(); }
	void fSetHandleCount() { PA = kernel32.oSetHandleCount; runASM(); }
	void fSetHandleInformation() { PA = kernel32.oSetHandleInformation; runASM(); }
	void fSetInformationJobObject() { PA = kernel32.oSetInformationJobObject; runASM(); }
	void fSetIoRateControlInformationJobObject() { PA = kernel32.oSetIoRateControlInformationJobObject; runASM(); }
	void fSetLastConsoleEventActive() { PA = kernel32.oSetLastConsoleEventActive; runASM(); }
	void fSetLastError() { PA = kernel32.oSetLastError; runASM(); }
	void fSetLocalPrimaryComputerNameA() { PA = kernel32.oSetLocalPrimaryComputerNameA; runASM(); }
	void fSetLocalPrimaryComputerNameW() { PA = kernel32.oSetLocalPrimaryComputerNameW; runASM(); }
	void fSetLocalTime() { PA = kernel32.oSetLocalTime; runASM(); }
	void fSetLocaleInfoA() { PA = kernel32.oSetLocaleInfoA; runASM(); }
	void fSetLocaleInfoW() { PA = kernel32.oSetLocaleInfoW; runASM(); }
	void fSetMailslotInfo() { PA = kernel32.oSetMailslotInfo; runASM(); }
	void fSetMessageWaitingIndicator() { PA = kernel32.oSetMessageWaitingIndicator; runASM(); }
	void fSetNamedPipeAttribute() { PA = kernel32.oSetNamedPipeAttribute; runASM(); }
	void fSetNamedPipeHandleState() { PA = kernel32.oSetNamedPipeHandleState; runASM(); }
	void fSetPriorityClass() { PA = kernel32.oSetPriorityClass; runASM(); }
	void fSetProcessAffinityMask() { PA = kernel32.oSetProcessAffinityMask; runASM(); }
	void fSetProcessAffinityUpdateMode() { PA = kernel32.oSetProcessAffinityUpdateMode; runASM(); }
	void fSetProcessDEPPolicy() { PA = kernel32.oSetProcessDEPPolicy; runASM(); }
	void fSetProcessDefaultCpuSets() { PA = kernel32.oSetProcessDefaultCpuSets; runASM(); }
	void fSetProcessInformation() { PA = kernel32.oSetProcessInformation; runASM(); }
	void fSetProcessMitigationPolicy() { PA = kernel32.oSetProcessMitigationPolicy; runASM(); }
	void fSetProcessPreferredUILanguages() { PA = kernel32.oSetProcessPreferredUILanguages; runASM(); }
	void fSetProcessPriorityBoost() { PA = kernel32.oSetProcessPriorityBoost; runASM(); }
	void fSetProcessShutdownParameters() { PA = kernel32.oSetProcessShutdownParameters; runASM(); }
	void fSetProcessWorkingSetSize() { PA = kernel32.oSetProcessWorkingSetSize; runASM(); }
	void fSetProcessWorkingSetSizeEx() { PA = kernel32.oSetProcessWorkingSetSizeEx; runASM(); }
	void fSetProtectedPolicy() { PA = kernel32.oSetProtectedPolicy; runASM(); }
	void fSetSearchPathMode() { PA = kernel32.oSetSearchPathMode; runASM(); }
	void fSetStdHandle() { PA = kernel32.oSetStdHandle; runASM(); }
	void fSetStdHandleEx() { PA = kernel32.oSetStdHandleEx; runASM(); }
	void fSetSystemFileCacheSize() { PA = kernel32.oSetSystemFileCacheSize; runASM(); }
	void fSetSystemPowerState() { PA = kernel32.oSetSystemPowerState; runASM(); }
	void fSetSystemTime() { PA = kernel32.oSetSystemTime; runASM(); }
	void fSetSystemTimeAdjustment() { PA = kernel32.oSetSystemTimeAdjustment; runASM(); }
	void fSetTapeParameters() { PA = kernel32.oSetTapeParameters; runASM(); }
	void fSetTapePosition() { PA = kernel32.oSetTapePosition; runASM(); }
	void fSetTermsrvAppInstallMode() { PA = kernel32.oSetTermsrvAppInstallMode; runASM(); }
	void fSetThreadAffinityMask() { PA = kernel32.oSetThreadAffinityMask; runASM(); }
	void fSetThreadContext() { PA = kernel32.oSetThreadContext; runASM(); }
	void fSetThreadDescription() { PA = kernel32.oSetThreadDescription; runASM(); }
	void fSetThreadErrorMode() { PA = kernel32.oSetThreadErrorMode; runASM(); }
	void fSetThreadExecutionState() { PA = kernel32.oSetThreadExecutionState; runASM(); }
	void fSetThreadGroupAffinity() { PA = kernel32.oSetThreadGroupAffinity; runASM(); }
	void fSetThreadIdealProcessor() { PA = kernel32.oSetThreadIdealProcessor; runASM(); }
	void fSetThreadIdealProcessorEx() { PA = kernel32.oSetThreadIdealProcessorEx; runASM(); }
	void fSetThreadInformation() { PA = kernel32.oSetThreadInformation; runASM(); }
	void fSetThreadLocale() { PA = kernel32.oSetThreadLocale; runASM(); }
	void fSetThreadPreferredUILanguages() { PA = kernel32.oSetThreadPreferredUILanguages; runASM(); }
	void fSetThreadPriority() { PA = kernel32.oSetThreadPriority; runASM(); }
	void fSetThreadPriorityBoost() { PA = kernel32.oSetThreadPriorityBoost; runASM(); }
	void fSetThreadSelectedCpuSets() { PA = kernel32.oSetThreadSelectedCpuSets; runASM(); }
	void fSetThreadStackGuarantee() { PA = kernel32.oSetThreadStackGuarantee; runASM(); }
	void fSetThreadToken() { PA = kernel32.oSetThreadToken; runASM(); }
	void fSetThreadUILanguage() { PA = kernel32.oSetThreadUILanguage; runASM(); }
	void fSetThreadpoolStackInformation() { PA = kernel32.oSetThreadpoolStackInformation; runASM(); }
	void fSetThreadpoolThreadMaximum() { PA = kernel32.oSetThreadpoolThreadMaximum; runASM(); }
	void fSetThreadpoolThreadMinimum() { PA = kernel32.oSetThreadpoolThreadMinimum; runASM(); }
	void fSetThreadpoolTimer() { PA = kernel32.oSetThreadpoolTimer; runASM(); }
	void fSetThreadpoolTimerEx() { PA = kernel32.oSetThreadpoolTimerEx; runASM(); }
	void fSetThreadpoolWait() { PA = kernel32.oSetThreadpoolWait; runASM(); }
	void fSetThreadpoolWaitEx() { PA = kernel32.oSetThreadpoolWaitEx; runASM(); }
	void fSetTimeZoneInformation() { PA = kernel32.oSetTimeZoneInformation; runASM(); }
	void fSetTimerQueueTimer() { PA = kernel32.oSetTimerQueueTimer; runASM(); }
	void fSetUmsThreadInformation() { PA = kernel32.oSetUmsThreadInformation; runASM(); }
	void fSetUnhandledExceptionFilter() { PA = kernel32.oSetUnhandledExceptionFilter; runASM(); }
	void fSetUserGeoID() { PA = kernel32.oSetUserGeoID; runASM(); }
	void fSetUserGeoName() { PA = kernel32.oSetUserGeoName; runASM(); }
	void fSetVDMCurrentDirectories() { PA = kernel32.oSetVDMCurrentDirectories; runASM(); }
	void fSetVolumeLabelA() { PA = kernel32.oSetVolumeLabelA; runASM(); }
	void fSetVolumeLabelW() { PA = kernel32.oSetVolumeLabelW; runASM(); }
	void fSetVolumeMountPointA() { PA = kernel32.oSetVolumeMountPointA; runASM(); }
	void fSetVolumeMountPointW() { PA = kernel32.oSetVolumeMountPointW; runASM(); }
	void fSetVolumeMountPointWStub() { PA = kernel32.oSetVolumeMountPointWStub; runASM(); }
	void fSetWaitableTimer() { PA = kernel32.oSetWaitableTimer; runASM(); }
	void fSetWaitableTimerEx() { PA = kernel32.oSetWaitableTimerEx; runASM(); }
	void fSetXStateFeaturesMask() { PA = kernel32.oSetXStateFeaturesMask; runASM(); }
	void fSetupComm() { PA = kernel32.oSetupComm; runASM(); }
	void fShowConsoleCursor() { PA = kernel32.oShowConsoleCursor; runASM(); }
	void fSignalObjectAndWait() { PA = kernel32.oSignalObjectAndWait; runASM(); }
	void fSizeofResource() { PA = kernel32.oSizeofResource; runASM(); }
	void fSleep() { PA = kernel32.oSleep; runASM(); }
	void fSleepConditionVariableCS() { PA = kernel32.oSleepConditionVariableCS; runASM(); }
	void fSleepConditionVariableSRW() { PA = kernel32.oSleepConditionVariableSRW; runASM(); }
	void fSleepEx() { PA = kernel32.oSleepEx; runASM(); }
	void fSortCloseHandle() { PA = kernel32.oSortCloseHandle; runASM(); }
	void fSortGetHandle() { PA = kernel32.oSortGetHandle; runASM(); }
	void fStartThreadpoolIo() { PA = kernel32.oStartThreadpoolIo; runASM(); }
	void fSubmitThreadpoolWork() { PA = kernel32.oSubmitThreadpoolWork; runASM(); }
	void fSuspendThread() { PA = kernel32.oSuspendThread; runASM(); }
	void fSwitchToFiber() { PA = kernel32.oSwitchToFiber; runASM(); }
	void fSwitchToThread() { PA = kernel32.oSwitchToThread; runASM(); }
	void fSystemTimeToFileTime() { PA = kernel32.oSystemTimeToFileTime; runASM(); }
	void fSystemTimeToTzSpecificLocalTime() { PA = kernel32.oSystemTimeToTzSpecificLocalTime; runASM(); }
	void fSystemTimeToTzSpecificLocalTimeEx() { PA = kernel32.oSystemTimeToTzSpecificLocalTimeEx; runASM(); }
	void fTerminateJobObject() { PA = kernel32.oTerminateJobObject; runASM(); }
	void fTerminateProcess() { PA = kernel32.oTerminateProcess; runASM(); }
	void fTerminateThread() { PA = kernel32.oTerminateThread; runASM(); }
	void fTermsrvAppInstallMode() { PA = kernel32.oTermsrvAppInstallMode; runASM(); }
	void fTermsrvConvertSysRootToUserDir() { PA = kernel32.oTermsrvConvertSysRootToUserDir; runASM(); }
	void fTermsrvCreateRegEntry() { PA = kernel32.oTermsrvCreateRegEntry; runASM(); }
	void fTermsrvDeleteKey() { PA = kernel32.oTermsrvDeleteKey; runASM(); }
	void fTermsrvDeleteValue() { PA = kernel32.oTermsrvDeleteValue; runASM(); }
	void fTermsrvGetPreSetValue() { PA = kernel32.oTermsrvGetPreSetValue; runASM(); }
	void fTermsrvGetWindowsDirectoryA() { PA = kernel32.oTermsrvGetWindowsDirectoryA; runASM(); }
	void fTermsrvGetWindowsDirectoryW() { PA = kernel32.oTermsrvGetWindowsDirectoryW; runASM(); }
	void fTermsrvOpenRegEntry() { PA = kernel32.oTermsrvOpenRegEntry; runASM(); }
	void fTermsrvOpenUserClasses() { PA = kernel32.oTermsrvOpenUserClasses; runASM(); }
	void fTermsrvRestoreKey() { PA = kernel32.oTermsrvRestoreKey; runASM(); }
	void fTermsrvSetKeySecurity() { PA = kernel32.oTermsrvSetKeySecurity; runASM(); }
	void fTermsrvSetValueKey() { PA = kernel32.oTermsrvSetValueKey; runASM(); }
	void fTermsrvSyncUserIniFileExt() { PA = kernel32.oTermsrvSyncUserIniFileExt; runASM(); }
	void fThread32First() { PA = kernel32.oThread32First; runASM(); }
	void fThread32Next() { PA = kernel32.oThread32Next; runASM(); }
	void fTlsAlloc() { PA = kernel32.oTlsAlloc; runASM(); }
	void fTlsFree() { PA = kernel32.oTlsFree; runASM(); }
	void fTlsGetValue() { PA = kernel32.oTlsGetValue; runASM(); }
	void fTlsSetValue() { PA = kernel32.oTlsSetValue; runASM(); }
	void fToolhelp32ReadProcessMemory() { PA = kernel32.oToolhelp32ReadProcessMemory; runASM(); }
	void fTransactNamedPipe() { PA = kernel32.oTransactNamedPipe; runASM(); }
	void fTransmitCommChar() { PA = kernel32.oTransmitCommChar; runASM(); }
	void fTryAcquireSRWLockExclusive() { PA = kernel32.oTryAcquireSRWLockExclusive; runASM(); }
	void fTryAcquireSRWLockShared() { PA = kernel32.oTryAcquireSRWLockShared; runASM(); }
	void fTryEnterCriticalSection() { PA = kernel32.oTryEnterCriticalSection; runASM(); }
	void fTrySubmitThreadpoolCallback() { PA = kernel32.oTrySubmitThreadpoolCallback; runASM(); }
	void fTzSpecificLocalTimeToSystemTime() { PA = kernel32.oTzSpecificLocalTimeToSystemTime; runASM(); }
	void fTzSpecificLocalTimeToSystemTimeEx() { PA = kernel32.oTzSpecificLocalTimeToSystemTimeEx; runASM(); }
	void fUTRegister() { PA = kernel32.oUTRegister; runASM(); }
	void fUTUnRegister() { PA = kernel32.oUTUnRegister; runASM(); }
	void fUmsThreadYield() { PA = kernel32.oUmsThreadYield; runASM(); }
	void fUnhandledExceptionFilter() { PA = kernel32.oUnhandledExceptionFilter; runASM(); }
	void fUnlockFile() { PA = kernel32.oUnlockFile; runASM(); }
	void fUnlockFileEx() { PA = kernel32.oUnlockFileEx; runASM(); }
	void fUnmapViewOfFile() { PA = kernel32.oUnmapViewOfFile; runASM(); }
	void fUnmapViewOfFileEx() { PA = kernel32.oUnmapViewOfFileEx; runASM(); }
	void fUnregisterApplicationRecoveryCallback() { PA = kernel32.oUnregisterApplicationRecoveryCallback; runASM(); }
	void fUnregisterApplicationRestart() { PA = kernel32.oUnregisterApplicationRestart; runASM(); }
	void fUnregisterBadMemoryNotification() { PA = kernel32.oUnregisterBadMemoryNotification; runASM(); }
	void fUnregisterConsoleIME() { PA = kernel32.oUnregisterConsoleIME; runASM(); }
	void fUnregisterWait() { PA = kernel32.oUnregisterWait; runASM(); }
	void fUnregisterWaitEx() { PA = kernel32.oUnregisterWaitEx; runASM(); }
	void fUnregisterWaitUntilOOBECompleted() { PA = kernel32.oUnregisterWaitUntilOOBECompleted; runASM(); }
	void fUpdateCalendarDayOfWeek() { PA = kernel32.oUpdateCalendarDayOfWeek; runASM(); }
	void fUpdateProcThreadAttribute() { PA = kernel32.oUpdateProcThreadAttribute; runASM(); }
	void fUpdateResourceA() { PA = kernel32.oUpdateResourceA; runASM(); }
	void fUpdateResourceW() { PA = kernel32.oUpdateResourceW; runASM(); }
	void fVDMConsoleOperation() { PA = kernel32.oVDMConsoleOperation; runASM(); }
	void fVDMOperationStarted() { PA = kernel32.oVDMOperationStarted; runASM(); }
	void fVerLanguageNameA() { PA = kernel32.oVerLanguageNameA; runASM(); }
	void fVerLanguageNameW() { PA = kernel32.oVerLanguageNameW; runASM(); }
	void fVerSetConditionMask() { PA = kernel32.oVerSetConditionMask; runASM(); }
	void fVerifyConsoleIoHandle() { PA = kernel32.oVerifyConsoleIoHandle; runASM(); }
	void fVerifyScripts() { PA = kernel32.oVerifyScripts; runASM(); }
	void fVerifyVersionInfoA() { PA = kernel32.oVerifyVersionInfoA; runASM(); }
	void fVerifyVersionInfoW() { PA = kernel32.oVerifyVersionInfoW; runASM(); }
	void fVirtualAlloc() { PA = kernel32.oVirtualAlloc; runASM(); }
	void fVirtualAllocEx() { PA = kernel32.oVirtualAllocEx; runASM(); }
	void fVirtualAllocExNuma() { PA = kernel32.oVirtualAllocExNuma; runASM(); }
	void fVirtualFree() { PA = kernel32.oVirtualFree; runASM(); }
	void fVirtualFreeEx() { PA = kernel32.oVirtualFreeEx; runASM(); }
	void fVirtualLock() { PA = kernel32.oVirtualLock; runASM(); }
	void fVirtualProtect() { PA = kernel32.oVirtualProtect; runASM(); }
	void fVirtualProtectEx() { PA = kernel32.oVirtualProtectEx; runASM(); }
	void fVirtualQuery() { PA = kernel32.oVirtualQuery; runASM(); }
	void fVirtualQueryEx() { PA = kernel32.oVirtualQueryEx; runASM(); }
	void fVirtualUnlock() { PA = kernel32.oVirtualUnlock; runASM(); }
	void fWTSGetActiveConsoleSessionId() { PA = kernel32.oWTSGetActiveConsoleSessionId; runASM(); }
	void fWaitCommEvent() { PA = kernel32.oWaitCommEvent; runASM(); }
	void fWaitForDebugEvent() { PA = kernel32.oWaitForDebugEvent; runASM(); }
	void fWaitForDebugEventEx() { PA = kernel32.oWaitForDebugEventEx; runASM(); }
	void fWaitForMultipleObjects() { PA = kernel32.oWaitForMultipleObjects; runASM(); }
	void fWaitForMultipleObjectsEx() { PA = kernel32.oWaitForMultipleObjectsEx; runASM(); }
	void fWaitForSingleObject() { PA = kernel32.oWaitForSingleObject; runASM(); }
	void fWaitForSingleObjectEx() { PA = kernel32.oWaitForSingleObjectEx; runASM(); }
	void fWaitForThreadpoolIoCallbacks() { PA = kernel32.oWaitForThreadpoolIoCallbacks; runASM(); }
	void fWaitForThreadpoolTimerCallbacks() { PA = kernel32.oWaitForThreadpoolTimerCallbacks; runASM(); }
	void fWaitForThreadpoolWaitCallbacks() { PA = kernel32.oWaitForThreadpoolWaitCallbacks; runASM(); }
	void fWaitForThreadpoolWorkCallbacks() { PA = kernel32.oWaitForThreadpoolWorkCallbacks; runASM(); }
	void fWaitNamedPipeA() { PA = kernel32.oWaitNamedPipeA; runASM(); }
	void fWaitNamedPipeW() { PA = kernel32.oWaitNamedPipeW; runASM(); }
	void fWakeAllConditionVariable() { PA = kernel32.oWakeAllConditionVariable; runASM(); }
	void fWakeConditionVariable() { PA = kernel32.oWakeConditionVariable; runASM(); }
	void fWerGetFlags() { PA = kernel32.oWerGetFlags; runASM(); }
	void fWerGetFlagsWorker() { PA = kernel32.oWerGetFlagsWorker; runASM(); }
	void fWerRegisterAdditionalProcess() { PA = kernel32.oWerRegisterAdditionalProcess; runASM(); }
	void fWerRegisterAppLocalDump() { PA = kernel32.oWerRegisterAppLocalDump; runASM(); }
	void fWerRegisterCustomMetadata() { PA = kernel32.oWerRegisterCustomMetadata; runASM(); }
	void fWerRegisterExcludedMemoryBlock() { PA = kernel32.oWerRegisterExcludedMemoryBlock; runASM(); }
	void fWerRegisterFile() { PA = kernel32.oWerRegisterFile; runASM(); }
	void fWerRegisterFileWorker() { PA = kernel32.oWerRegisterFileWorker; runASM(); }
	void fWerRegisterMemoryBlock() { PA = kernel32.oWerRegisterMemoryBlock; runASM(); }
	void fWerRegisterMemoryBlockWorker() { PA = kernel32.oWerRegisterMemoryBlockWorker; runASM(); }
	void fWerRegisterRuntimeExceptionModule() { PA = kernel32.oWerRegisterRuntimeExceptionModule; runASM(); }
	void fWerRegisterRuntimeExceptionModuleWorker() { PA = kernel32.oWerRegisterRuntimeExceptionModuleWorker; runASM(); }
	void fWerSetFlags() { PA = kernel32.oWerSetFlags; runASM(); }
	void fWerSetFlagsWorker() { PA = kernel32.oWerSetFlagsWorker; runASM(); }
	void fWerUnregisterAdditionalProcess() { PA = kernel32.oWerUnregisterAdditionalProcess; runASM(); }
	void fWerUnregisterAppLocalDump() { PA = kernel32.oWerUnregisterAppLocalDump; runASM(); }
	void fWerUnregisterCustomMetadata() { PA = kernel32.oWerUnregisterCustomMetadata; runASM(); }
	void fWerUnregisterExcludedMemoryBlock() { PA = kernel32.oWerUnregisterExcludedMemoryBlock; runASM(); }
	void fWerUnregisterFile() { PA = kernel32.oWerUnregisterFile; runASM(); }
	void fWerUnregisterFileWorker() { PA = kernel32.oWerUnregisterFileWorker; runASM(); }
	void fWerUnregisterMemoryBlock() { PA = kernel32.oWerUnregisterMemoryBlock; runASM(); }
	void fWerUnregisterMemoryBlockWorker() { PA = kernel32.oWerUnregisterMemoryBlockWorker; runASM(); }
	void fWerUnregisterRuntimeExceptionModule() { PA = kernel32.oWerUnregisterRuntimeExceptionModule; runASM(); }
	void fWerUnregisterRuntimeExceptionModuleWorker() { PA = kernel32.oWerUnregisterRuntimeExceptionModuleWorker; runASM(); }
	void fWerpGetDebugger() { PA = kernel32.oWerpGetDebugger; runASM(); }
	void fWerpInitiateRemoteRecovery() { PA = kernel32.oWerpInitiateRemoteRecovery; runASM(); }
	void fWerpLaunchAeDebug() { PA = kernel32.oWerpLaunchAeDebug; runASM(); }
	void fWerpNotifyLoadStringResourceWorker() { PA = kernel32.oWerpNotifyLoadStringResourceWorker; runASM(); }
	void fWerpNotifyUseStringResourceWorker() { PA = kernel32.oWerpNotifyUseStringResourceWorker; runASM(); }
	void fWideCharToMultiByte() { PA = kernel32.oWideCharToMultiByte; runASM(); }
	void fWinExec() { PA = kernel32.oWinExec; runASM(); }
	void fWow64DisableWow64FsRedirection() { PA = kernel32.oWow64DisableWow64FsRedirection; runASM(); }
	void fWow64EnableWow64FsRedirection() { PA = kernel32.oWow64EnableWow64FsRedirection; runASM(); }
	void fWow64GetThreadContext() { PA = kernel32.oWow64GetThreadContext; runASM(); }
	void fWow64GetThreadSelectorEntry() { PA = kernel32.oWow64GetThreadSelectorEntry; runASM(); }
	void fWow64RevertWow64FsRedirection() { PA = kernel32.oWow64RevertWow64FsRedirection; runASM(); }
	void fWow64SetThreadContext() { PA = kernel32.oWow64SetThreadContext; runASM(); }
	void fWow64SuspendThread() { PA = kernel32.oWow64SuspendThread; runASM(); }
	void fWriteConsoleA() { PA = kernel32.oWriteConsoleA; runASM(); }
	void fWriteConsoleInputA() { PA = kernel32.oWriteConsoleInputA; runASM(); }
	void fWriteConsoleInputVDMA() { PA = kernel32.oWriteConsoleInputVDMA; runASM(); }
	void fWriteConsoleInputVDMW() { PA = kernel32.oWriteConsoleInputVDMW; runASM(); }
	void fWriteConsoleInputW() { PA = kernel32.oWriteConsoleInputW; runASM(); }
	void fWriteConsoleOutputA() { PA = kernel32.oWriteConsoleOutputA; runASM(); }
	void fWriteConsoleOutputAttribute() { PA = kernel32.oWriteConsoleOutputAttribute; runASM(); }
	void fWriteConsoleOutputCharacterA() { PA = kernel32.oWriteConsoleOutputCharacterA; runASM(); }
	void fWriteConsoleOutputCharacterW() { PA = kernel32.oWriteConsoleOutputCharacterW; runASM(); }
	void fWriteConsoleOutputW() { PA = kernel32.oWriteConsoleOutputW; runASM(); }
	void fWriteConsoleW() { PA = kernel32.oWriteConsoleW; runASM(); }
	void fWriteFile() { PA = kernel32.oWriteFile; runASM(); }
	void fWriteFileEx() { PA = kernel32.oWriteFileEx; runASM(); }
	void fWriteFileGather() { PA = kernel32.oWriteFileGather; runASM(); }
	void fWritePrivateProfileSectionA() { PA = kernel32.oWritePrivateProfileSectionA; runASM(); }
	void fWritePrivateProfileSectionW() { PA = kernel32.oWritePrivateProfileSectionW; runASM(); }
	void fWritePrivateProfileStringA() { PA = kernel32.oWritePrivateProfileStringA; runASM(); }
	void fWritePrivateProfileStringW() { PA = kernel32.oWritePrivateProfileStringW; runASM(); }
	void fWritePrivateProfileStructA() { PA = kernel32.oWritePrivateProfileStructA; runASM(); }
	void fWritePrivateProfileStructW() { PA = kernel32.oWritePrivateProfileStructW; runASM(); }
	void fWriteProcessMemory() { PA = kernel32.oWriteProcessMemory; runASM(); }
	void fWriteProfileSectionA() { PA = kernel32.oWriteProfileSectionA; runASM(); }
	void fWriteProfileSectionW() { PA = kernel32.oWriteProfileSectionW; runASM(); }
	void fWriteProfileStringA() { PA = kernel32.oWriteProfileStringA; runASM(); }
	void fWriteProfileStringW() { PA = kernel32.oWriteProfileStringW; runASM(); }
	void fWriteTapemark() { PA = kernel32.oWriteTapemark; runASM(); }
	void fZombifyActCtx() { PA = kernel32.oZombifyActCtx; runASM(); }
	void fZombifyActCtxWorker() { PA = kernel32.oZombifyActCtxWorker; runASM(); }
	void f__C_specific_handler() { PA = kernel32.o__C_specific_handler; runASM(); }
	void f__chkstk() { PA = kernel32.o__chkstk; runASM(); }
	void f__misaligned_access() { PA = kernel32.o__misaligned_access; runASM(); }
	void f_hread() { PA = kernel32.o_hread; runASM(); }
	void f_hwrite() { PA = kernel32.o_hwrite; runASM(); }
	void f_lclose() { PA = kernel32.o_lclose; runASM(); }
	void f_lcreat() { PA = kernel32.o_lcreat; runASM(); }
	void f_llseek() { PA = kernel32.o_llseek; runASM(); }
	void f_local_unwind() { PA = kernel32.o_local_unwind; runASM(); }
	void f_lopen() { PA = kernel32.o_lopen; runASM(); }
	void f_lread() { PA = kernel32.o_lread; runASM(); }
	void f_lwrite() { PA = kernel32.o_lwrite; runASM(); }
	void flstrcat() { PA = kernel32.olstrcat; runASM(); }
	void flstrcatA() { PA = kernel32.olstrcatA; runASM(); }
	void flstrcatW() { PA = kernel32.olstrcatW; runASM(); }
	void flstrcmp() { PA = kernel32.olstrcmp; runASM(); }
	void flstrcmpA() { PA = kernel32.olstrcmpA; runASM(); }
	void flstrcmpW() { PA = kernel32.olstrcmpW; runASM(); }
	void flstrcmpi() { PA = kernel32.olstrcmpi; runASM(); }
	void flstrcmpiA() { PA = kernel32.olstrcmpiA; runASM(); }
	void flstrcmpiW() { PA = kernel32.olstrcmpiW; runASM(); }
	void flstrcpy() { PA = kernel32.olstrcpy; runASM(); }
	void flstrcpyA() { PA = kernel32.olstrcpyA; runASM(); }
	void flstrcpyW() { PA = kernel32.olstrcpyW; runASM(); }
	void flstrcpyn() { PA = kernel32.olstrcpyn; runASM(); }
	void flstrcpynA() { PA = kernel32.olstrcpynA; runASM(); }
	void flstrcpynW() { PA = kernel32.olstrcpynW; runASM(); }
	void flstrlen() { PA = kernel32.olstrlen; runASM(); }
	void flstrlenA() { PA = kernel32.olstrlenA; runASM(); }
	void flstrlenW() { PA = kernel32.olstrlenW; runASM(); }
	void ftimeBeginPeriod() { PA = kernel32.otimeBeginPeriod; runASM(); }
	void ftimeEndPeriod() { PA = kernel32.otimeEndPeriod; runASM(); }
	void ftimeGetDevCaps() { PA = kernel32.otimeGetDevCaps; runASM(); }
	void ftimeGetSystemTime() { PA = kernel32.otimeGetSystemTime; runASM(); }
	void ftimeGetTime() { PA = kernel32.otimeGetTime; runASM(); }
	void fuaw_lstrcmpW() { PA = kernel32.ouaw_lstrcmpW; runASM(); }
	void fuaw_lstrcmpiW() { PA = kernel32.ouaw_lstrcmpiW; runASM(); }
	void fuaw_lstrlenW() { PA = kernel32.ouaw_lstrlenW; runASM(); }
	void fuaw_wcschr() { PA = kernel32.ouaw_wcschr; runASM(); }
	void fuaw_wcscpy() { PA = kernel32.ouaw_wcscpy; runASM(); }
	void fuaw_wcsicmp() { PA = kernel32.ouaw_wcsicmp; runASM(); }
	void fuaw_wcslen() { PA = kernel32.ouaw_wcslen; runASM(); }
	void fuaw_wcsrchr() { PA = kernel32.ouaw_wcsrchr; runASM(); }
}

void setupFunctions() {
	kernel32.oAcquireSRWLockExclusive = GetProcAddress(kernel32.dll, "AcquireSRWLockExclusive");
	kernel32.oAcquireSRWLockShared = GetProcAddress(kernel32.dll, "AcquireSRWLockShared");
	kernel32.oActivateActCtx = GetProcAddress(kernel32.dll, "ActivateActCtx");
	kernel32.oActivateActCtxWorker = GetProcAddress(kernel32.dll, "ActivateActCtxWorker");
	kernel32.oAddAtomA = GetProcAddress(kernel32.dll, "AddAtomA");
	kernel32.oAddAtomW = GetProcAddress(kernel32.dll, "AddAtomW");
	kernel32.oAddConsoleAliasA = GetProcAddress(kernel32.dll, "AddConsoleAliasA");
	kernel32.oAddConsoleAliasW = GetProcAddress(kernel32.dll, "AddConsoleAliasW");
	kernel32.oAddDllDirectory = GetProcAddress(kernel32.dll, "AddDllDirectory");
	kernel32.oAddIntegrityLabelToBoundaryDescriptor = GetProcAddress(kernel32.dll, "AddIntegrityLabelToBoundaryDescriptor");
	kernel32.oAddLocalAlternateComputerNameA = GetProcAddress(kernel32.dll, "AddLocalAlternateComputerNameA");
	kernel32.oAddLocalAlternateComputerNameW = GetProcAddress(kernel32.dll, "AddLocalAlternateComputerNameW");
	kernel32.oAddRefActCtx = GetProcAddress(kernel32.dll, "AddRefActCtx");
	kernel32.oAddRefActCtxWorker = GetProcAddress(kernel32.dll, "AddRefActCtxWorker");
	kernel32.oAddResourceAttributeAce = GetProcAddress(kernel32.dll, "AddResourceAttributeAce");
	kernel32.oAddSIDToBoundaryDescriptor = GetProcAddress(kernel32.dll, "AddSIDToBoundaryDescriptor");
	kernel32.oAddScopedPolicyIDAce = GetProcAddress(kernel32.dll, "AddScopedPolicyIDAce");
	kernel32.oAddSecureMemoryCacheCallback = GetProcAddress(kernel32.dll, "AddSecureMemoryCacheCallback");
	kernel32.oAddVectoredContinueHandler = GetProcAddress(kernel32.dll, "AddVectoredContinueHandler");
	kernel32.oAddVectoredExceptionHandler = GetProcAddress(kernel32.dll, "AddVectoredExceptionHandler");
	kernel32.oAdjustCalendarDate = GetProcAddress(kernel32.dll, "AdjustCalendarDate");
	kernel32.oAllocConsole = GetProcAddress(kernel32.dll, "AllocConsole");
	kernel32.oAllocateUserPhysicalPages = GetProcAddress(kernel32.dll, "AllocateUserPhysicalPages");
	kernel32.oAllocateUserPhysicalPagesNuma = GetProcAddress(kernel32.dll, "AllocateUserPhysicalPagesNuma");
	kernel32.oAppPolicyGetClrCompat = GetProcAddress(kernel32.dll, "AppPolicyGetClrCompat");
	kernel32.oAppPolicyGetCreateFileAccess = GetProcAddress(kernel32.dll, "AppPolicyGetCreateFileAccess");
	kernel32.oAppPolicyGetLifecycleManagement = GetProcAddress(kernel32.dll, "AppPolicyGetLifecycleManagement");
	kernel32.oAppPolicyGetMediaFoundationCodecLoading = GetProcAddress(kernel32.dll, "AppPolicyGetMediaFoundationCodecLoading");
	kernel32.oAppPolicyGetProcessTerminationMethod = GetProcAddress(kernel32.dll, "AppPolicyGetProcessTerminationMethod");
	kernel32.oAppPolicyGetShowDeveloperDiagnostic = GetProcAddress(kernel32.dll, "AppPolicyGetShowDeveloperDiagnostic");
	kernel32.oAppPolicyGetThreadInitializationType = GetProcAddress(kernel32.dll, "AppPolicyGetThreadInitializationType");
	kernel32.oAppPolicyGetWindowingModel = GetProcAddress(kernel32.dll, "AppPolicyGetWindowingModel");
	kernel32.oAppXGetOSMaxVersionTested = GetProcAddress(kernel32.dll, "AppXGetOSMaxVersionTested");
	kernel32.oApplicationRecoveryFinished = GetProcAddress(kernel32.dll, "ApplicationRecoveryFinished");
	kernel32.oApplicationRecoveryInProgress = GetProcAddress(kernel32.dll, "ApplicationRecoveryInProgress");
	kernel32.oAreFileApisANSI = GetProcAddress(kernel32.dll, "AreFileApisANSI");
	kernel32.oAssignProcessToJobObject = GetProcAddress(kernel32.dll, "AssignProcessToJobObject");
	kernel32.oAttachConsole = GetProcAddress(kernel32.dll, "AttachConsole");
	kernel32.oBackupRead = GetProcAddress(kernel32.dll, "BackupRead");
	kernel32.oBackupSeek = GetProcAddress(kernel32.dll, "BackupSeek");
	kernel32.oBackupWrite = GetProcAddress(kernel32.dll, "BackupWrite");
	kernel32.oBaseCheckAppcompatCache = GetProcAddress(kernel32.dll, "BaseCheckAppcompatCache");
	kernel32.oBaseCheckAppcompatCacheEx = GetProcAddress(kernel32.dll, "BaseCheckAppcompatCacheEx");
	kernel32.oBaseCheckAppcompatCacheExWorker = GetProcAddress(kernel32.dll, "BaseCheckAppcompatCacheExWorker");
	kernel32.oBaseCheckAppcompatCacheWorker = GetProcAddress(kernel32.dll, "BaseCheckAppcompatCacheWorker");
	kernel32.oBaseCheckElevation = GetProcAddress(kernel32.dll, "BaseCheckElevation");
	kernel32.oBaseCleanupAppcompatCacheSupport = GetProcAddress(kernel32.dll, "BaseCleanupAppcompatCacheSupport");
	kernel32.oBaseCleanupAppcompatCacheSupportWorker = GetProcAddress(kernel32.dll, "BaseCleanupAppcompatCacheSupportWorker");
	kernel32.oBaseDestroyVDMEnvironment = GetProcAddress(kernel32.dll, "BaseDestroyVDMEnvironment");
	kernel32.oBaseDllReadWriteIniFile = GetProcAddress(kernel32.dll, "BaseDllReadWriteIniFile");
	kernel32.oBaseDumpAppcompatCache = GetProcAddress(kernel32.dll, "BaseDumpAppcompatCache");
	kernel32.oBaseDumpAppcompatCacheWorker = GetProcAddress(kernel32.dll, "BaseDumpAppcompatCacheWorker");
	kernel32.oBaseElevationPostProcessing = GetProcAddress(kernel32.dll, "BaseElevationPostProcessing");
	kernel32.oBaseFlushAppcompatCache = GetProcAddress(kernel32.dll, "BaseFlushAppcompatCache");
	kernel32.oBaseFlushAppcompatCacheWorker = GetProcAddress(kernel32.dll, "BaseFlushAppcompatCacheWorker");
	kernel32.oBaseFormatObjectAttributes = GetProcAddress(kernel32.dll, "BaseFormatObjectAttributes");
	kernel32.oBaseFormatTimeOut = GetProcAddress(kernel32.dll, "BaseFormatTimeOut");
	kernel32.oBaseFreeAppCompatDataForProcessWorker = GetProcAddress(kernel32.dll, "BaseFreeAppCompatDataForProcessWorker");
	kernel32.oBaseGenerateAppCompatData = GetProcAddress(kernel32.dll, "BaseGenerateAppCompatData");
	kernel32.oBaseGetNamedObjectDirectory = GetProcAddress(kernel32.dll, "BaseGetNamedObjectDirectory");
	kernel32.oBaseInitAppcompatCacheSupport = GetProcAddress(kernel32.dll, "BaseInitAppcompatCacheSupport");
	kernel32.oBaseInitAppcompatCacheSupportWorker = GetProcAddress(kernel32.dll, "BaseInitAppcompatCacheSupportWorker");
	kernel32.oBaseIsAppcompatInfrastructureDisabled = GetProcAddress(kernel32.dll, "BaseIsAppcompatInfrastructureDisabled");
	kernel32.oBaseIsAppcompatInfrastructureDisabledWorker = GetProcAddress(kernel32.dll, "BaseIsAppcompatInfrastructureDisabledWorker");
	kernel32.oBaseIsDosApplication = GetProcAddress(kernel32.dll, "BaseIsDosApplication");
	kernel32.oBaseQueryModuleData = GetProcAddress(kernel32.dll, "BaseQueryModuleData");
	kernel32.oBaseReadAppCompatDataForProcessWorker = GetProcAddress(kernel32.dll, "BaseReadAppCompatDataForProcessWorker");
	kernel32.oBaseSetLastNTError = GetProcAddress(kernel32.dll, "BaseSetLastNTError");
	kernel32.oBaseThreadInitThunk = GetProcAddress(kernel32.dll, "BaseThreadInitThunk");
	kernel32.oBaseUpdateAppcompatCache = GetProcAddress(kernel32.dll, "BaseUpdateAppcompatCache");
	kernel32.oBaseUpdateAppcompatCacheWorker = GetProcAddress(kernel32.dll, "BaseUpdateAppcompatCacheWorker");
	kernel32.oBaseUpdateVDMEntry = GetProcAddress(kernel32.dll, "BaseUpdateVDMEntry");
	kernel32.oBaseVerifyUnicodeString = GetProcAddress(kernel32.dll, "BaseVerifyUnicodeString");
	kernel32.oBaseWriteErrorElevationRequiredEvent = GetProcAddress(kernel32.dll, "BaseWriteErrorElevationRequiredEvent");
	kernel32.oBasep8BitStringToDynamicUnicodeString = GetProcAddress(kernel32.dll, "Basep8BitStringToDynamicUnicodeString");
	kernel32.oBasepAllocateActivationContextActivationBlock = GetProcAddress(kernel32.dll, "BasepAllocateActivationContextActivationBlock");
	kernel32.oBasepAnsiStringToDynamicUnicodeString = GetProcAddress(kernel32.dll, "BasepAnsiStringToDynamicUnicodeString");
	kernel32.oBasepAppContainerEnvironmentExtension = GetProcAddress(kernel32.dll, "BasepAppContainerEnvironmentExtension");
	kernel32.oBasepAppXExtension = GetProcAddress(kernel32.dll, "BasepAppXExtension");
	kernel32.oBasepCheckAppCompat = GetProcAddress(kernel32.dll, "BasepCheckAppCompat");
	kernel32.oBasepCheckWebBladeHashes = GetProcAddress(kernel32.dll, "BasepCheckWebBladeHashes");
	kernel32.oBasepCheckWinSaferRestrictions = GetProcAddress(kernel32.dll, "BasepCheckWinSaferRestrictions");
	kernel32.oBasepConstructSxsCreateProcessMessage = GetProcAddress(kernel32.dll, "BasepConstructSxsCreateProcessMessage");
	kernel32.oBasepCopyEncryption = GetProcAddress(kernel32.dll, "BasepCopyEncryption");
	kernel32.oBasepFreeActivationContextActivationBlock = GetProcAddress(kernel32.dll, "BasepFreeActivationContextActivationBlock");
	kernel32.oBasepFreeAppCompatData = GetProcAddress(kernel32.dll, "BasepFreeAppCompatData");
	kernel32.oBasepGetAppCompatData = GetProcAddress(kernel32.dll, "BasepGetAppCompatData");
	kernel32.oBasepGetComputerNameFromNtPath = GetProcAddress(kernel32.dll, "BasepGetComputerNameFromNtPath");
	kernel32.oBasepGetExeArchType = GetProcAddress(kernel32.dll, "BasepGetExeArchType");
	kernel32.oBasepInitAppCompatData = GetProcAddress(kernel32.dll, "BasepInitAppCompatData");
	kernel32.oBasepIsProcessAllowed = GetProcAddress(kernel32.dll, "BasepIsProcessAllowed");
	kernel32.oBasepMapModuleHandle = GetProcAddress(kernel32.dll, "BasepMapModuleHandle");
	kernel32.oBasepNotifyLoadStringResource = GetProcAddress(kernel32.dll, "BasepNotifyLoadStringResource");
	kernel32.oBasepPostSuccessAppXExtension = GetProcAddress(kernel32.dll, "BasepPostSuccessAppXExtension");
	kernel32.oBasepProcessInvalidImage = GetProcAddress(kernel32.dll, "BasepProcessInvalidImage");
	kernel32.oBasepQueryAppCompat = GetProcAddress(kernel32.dll, "BasepQueryAppCompat");
	kernel32.oBasepQueryModuleChpeSettings = GetProcAddress(kernel32.dll, "BasepQueryModuleChpeSettings");
	kernel32.oBasepReleaseAppXContext = GetProcAddress(kernel32.dll, "BasepReleaseAppXContext");
	kernel32.oBasepReleaseSxsCreateProcessUtilityStruct = GetProcAddress(kernel32.dll, "BasepReleaseSxsCreateProcessUtilityStruct");
	kernel32.oBasepReportFault = GetProcAddress(kernel32.dll, "BasepReportFault");
	kernel32.oBasepSetFileEncryptionCompression = GetProcAddress(kernel32.dll, "BasepSetFileEncryptionCompression");
	kernel32.oBeep = GetProcAddress(kernel32.dll, "Beep");
	kernel32.oBeginUpdateResourceA = GetProcAddress(kernel32.dll, "BeginUpdateResourceA");
	kernel32.oBeginUpdateResourceW = GetProcAddress(kernel32.dll, "BeginUpdateResourceW");
	kernel32.oBindIoCompletionCallback = GetProcAddress(kernel32.dll, "BindIoCompletionCallback");
	kernel32.oBuildCommDCBA = GetProcAddress(kernel32.dll, "BuildCommDCBA");
	kernel32.oBuildCommDCBAndTimeoutsA = GetProcAddress(kernel32.dll, "BuildCommDCBAndTimeoutsA");
	kernel32.oBuildCommDCBAndTimeoutsW = GetProcAddress(kernel32.dll, "BuildCommDCBAndTimeoutsW");
	kernel32.oBuildCommDCBW = GetProcAddress(kernel32.dll, "BuildCommDCBW");
	kernel32.oCallNamedPipeA = GetProcAddress(kernel32.dll, "CallNamedPipeA");
	kernel32.oCallNamedPipeW = GetProcAddress(kernel32.dll, "CallNamedPipeW");
	kernel32.oCallbackMayRunLong = GetProcAddress(kernel32.dll, "CallbackMayRunLong");
	kernel32.oCancelDeviceWakeupRequest = GetProcAddress(kernel32.dll, "CancelDeviceWakeupRequest");
	kernel32.oCancelIo = GetProcAddress(kernel32.dll, "CancelIo");
	kernel32.oCancelIoEx = GetProcAddress(kernel32.dll, "CancelIoEx");
	kernel32.oCancelSynchronousIo = GetProcAddress(kernel32.dll, "CancelSynchronousIo");
	kernel32.oCancelThreadpoolIo = GetProcAddress(kernel32.dll, "CancelThreadpoolIo");
	kernel32.oCancelTimerQueueTimer = GetProcAddress(kernel32.dll, "CancelTimerQueueTimer");
	kernel32.oCancelWaitableTimer = GetProcAddress(kernel32.dll, "CancelWaitableTimer");
	kernel32.oCeipIsOptedIn = GetProcAddress(kernel32.dll, "CeipIsOptedIn");
	kernel32.oChangeTimerQueueTimer = GetProcAddress(kernel32.dll, "ChangeTimerQueueTimer");
	kernel32.oCheckAllowDecryptedRemoteDestinationPolicy = GetProcAddress(kernel32.dll, "CheckAllowDecryptedRemoteDestinationPolicy");
	kernel32.oCheckElevation = GetProcAddress(kernel32.dll, "CheckElevation");
	kernel32.oCheckElevationEnabled = GetProcAddress(kernel32.dll, "CheckElevationEnabled");
	kernel32.oCheckForReadOnlyResource = GetProcAddress(kernel32.dll, "CheckForReadOnlyResource");
	kernel32.oCheckForReadOnlyResourceFilter = GetProcAddress(kernel32.dll, "CheckForReadOnlyResourceFilter");
	kernel32.oCheckNameLegalDOS8Dot3A = GetProcAddress(kernel32.dll, "CheckNameLegalDOS8Dot3A");
	kernel32.oCheckNameLegalDOS8Dot3W = GetProcAddress(kernel32.dll, "CheckNameLegalDOS8Dot3W");
	kernel32.oCheckRemoteDebuggerPresent = GetProcAddress(kernel32.dll, "CheckRemoteDebuggerPresent");
	kernel32.oCheckTokenCapability = GetProcAddress(kernel32.dll, "CheckTokenCapability");
	kernel32.oCheckTokenMembershipEx = GetProcAddress(kernel32.dll, "CheckTokenMembershipEx");
	kernel32.oClearCommBreak = GetProcAddress(kernel32.dll, "ClearCommBreak");
	kernel32.oClearCommError = GetProcAddress(kernel32.dll, "ClearCommError");
	kernel32.oCloseConsoleHandle = GetProcAddress(kernel32.dll, "CloseConsoleHandle");
	kernel32.oCloseHandle = GetProcAddress(kernel32.dll, "CloseHandle");
	kernel32.oClosePackageInfo = GetProcAddress(kernel32.dll, "ClosePackageInfo");
	kernel32.oClosePrivateNamespace = GetProcAddress(kernel32.dll, "ClosePrivateNamespace");
	kernel32.oCloseProfileUserMapping = GetProcAddress(kernel32.dll, "CloseProfileUserMapping");
	kernel32.oClosePseudoConsole = GetProcAddress(kernel32.dll, "ClosePseudoConsole");
	kernel32.oCloseState = GetProcAddress(kernel32.dll, "CloseState");
	kernel32.oCloseThreadpool = GetProcAddress(kernel32.dll, "CloseThreadpool");
	kernel32.oCloseThreadpoolCleanupGroup = GetProcAddress(kernel32.dll, "CloseThreadpoolCleanupGroup");
	kernel32.oCloseThreadpoolCleanupGroupMembers = GetProcAddress(kernel32.dll, "CloseThreadpoolCleanupGroupMembers");
	kernel32.oCloseThreadpoolIo = GetProcAddress(kernel32.dll, "CloseThreadpoolIo");
	kernel32.oCloseThreadpoolTimer = GetProcAddress(kernel32.dll, "CloseThreadpoolTimer");
	kernel32.oCloseThreadpoolWait = GetProcAddress(kernel32.dll, "CloseThreadpoolWait");
	kernel32.oCloseThreadpoolWork = GetProcAddress(kernel32.dll, "CloseThreadpoolWork");
	kernel32.oCmdBatNotification = GetProcAddress(kernel32.dll, "CmdBatNotification");
	kernel32.oCommConfigDialogA = GetProcAddress(kernel32.dll, "CommConfigDialogA");
	kernel32.oCommConfigDialogW = GetProcAddress(kernel32.dll, "CommConfigDialogW");
	kernel32.oCompareCalendarDates = GetProcAddress(kernel32.dll, "CompareCalendarDates");
	kernel32.oCompareFileTime = GetProcAddress(kernel32.dll, "CompareFileTime");
	kernel32.oCompareStringA = GetProcAddress(kernel32.dll, "CompareStringA");
	kernel32.oCompareStringEx = GetProcAddress(kernel32.dll, "CompareStringEx");
	kernel32.oCompareStringOrdinal = GetProcAddress(kernel32.dll, "CompareStringOrdinal");
	kernel32.oCompareStringW = GetProcAddress(kernel32.dll, "CompareStringW");
	kernel32.oConnectNamedPipe = GetProcAddress(kernel32.dll, "ConnectNamedPipe");
	kernel32.oConsoleMenuControl = GetProcAddress(kernel32.dll, "ConsoleMenuControl");
	kernel32.oContinueDebugEvent = GetProcAddress(kernel32.dll, "ContinueDebugEvent");
	kernel32.oConvertCalDateTimeToSystemTime = GetProcAddress(kernel32.dll, "ConvertCalDateTimeToSystemTime");
	kernel32.oConvertDefaultLocale = GetProcAddress(kernel32.dll, "ConvertDefaultLocale");
	kernel32.oConvertFiberToThread = GetProcAddress(kernel32.dll, "ConvertFiberToThread");
	kernel32.oConvertNLSDayOfWeekToWin32DayOfWeek = GetProcAddress(kernel32.dll, "ConvertNLSDayOfWeekToWin32DayOfWeek");
	kernel32.oConvertSystemTimeToCalDateTime = GetProcAddress(kernel32.dll, "ConvertSystemTimeToCalDateTime");
	kernel32.oConvertThreadToFiber = GetProcAddress(kernel32.dll, "ConvertThreadToFiber");
	kernel32.oConvertThreadToFiberEx = GetProcAddress(kernel32.dll, "ConvertThreadToFiberEx");
	kernel32.oCopyContext = GetProcAddress(kernel32.dll, "CopyContext");
	kernel32.oCopyFile2 = GetProcAddress(kernel32.dll, "CopyFile2");
	kernel32.oCopyFileA = GetProcAddress(kernel32.dll, "CopyFileA");
	kernel32.oCopyFileExA = GetProcAddress(kernel32.dll, "CopyFileExA");
	kernel32.oCopyFileExW = GetProcAddress(kernel32.dll, "CopyFileExW");
	kernel32.oCopyFileTransactedA = GetProcAddress(kernel32.dll, "CopyFileTransactedA");
	kernel32.oCopyFileTransactedW = GetProcAddress(kernel32.dll, "CopyFileTransactedW");
	kernel32.oCopyFileW = GetProcAddress(kernel32.dll, "CopyFileW");
	kernel32.oCopyLZFile = GetProcAddress(kernel32.dll, "CopyLZFile");
	kernel32.oCreateActCtxA = GetProcAddress(kernel32.dll, "CreateActCtxA");
	kernel32.oCreateActCtxW = GetProcAddress(kernel32.dll, "CreateActCtxW");
	kernel32.oCreateActCtxWWorker = GetProcAddress(kernel32.dll, "CreateActCtxWWorker");
	kernel32.oCreateBoundaryDescriptorA = GetProcAddress(kernel32.dll, "CreateBoundaryDescriptorA");
	kernel32.oCreateBoundaryDescriptorW = GetProcAddress(kernel32.dll, "CreateBoundaryDescriptorW");
	kernel32.oCreateConsoleScreenBuffer = GetProcAddress(kernel32.dll, "CreateConsoleScreenBuffer");
	kernel32.oCreateDirectoryA = GetProcAddress(kernel32.dll, "CreateDirectoryA");
	kernel32.oCreateDirectoryExA = GetProcAddress(kernel32.dll, "CreateDirectoryExA");
	kernel32.oCreateDirectoryExW = GetProcAddress(kernel32.dll, "CreateDirectoryExW");
	kernel32.oCreateDirectoryTransactedA = GetProcAddress(kernel32.dll, "CreateDirectoryTransactedA");
	kernel32.oCreateDirectoryTransactedW = GetProcAddress(kernel32.dll, "CreateDirectoryTransactedW");
	kernel32.oCreateDirectoryW = GetProcAddress(kernel32.dll, "CreateDirectoryW");
	kernel32.oCreateEnclave = GetProcAddress(kernel32.dll, "CreateEnclave");
	kernel32.oCreateEventA = GetProcAddress(kernel32.dll, "CreateEventA");
	kernel32.oCreateEventExA = GetProcAddress(kernel32.dll, "CreateEventExA");
	kernel32.oCreateEventExW = GetProcAddress(kernel32.dll, "CreateEventExW");
	kernel32.oCreateEventW = GetProcAddress(kernel32.dll, "CreateEventW");
	kernel32.oCreateFiber = GetProcAddress(kernel32.dll, "CreateFiber");
	kernel32.oCreateFiberEx = GetProcAddress(kernel32.dll, "CreateFiberEx");
	kernel32.oCreateFile2 = GetProcAddress(kernel32.dll, "CreateFile2");
	kernel32.oCreateFileA = GetProcAddress(kernel32.dll, "CreateFileA");
	kernel32.oCreateFileMappingA = GetProcAddress(kernel32.dll, "CreateFileMappingA");
	kernel32.oCreateFileMappingFromApp = GetProcAddress(kernel32.dll, "CreateFileMappingFromApp");
	kernel32.oCreateFileMappingNumaA = GetProcAddress(kernel32.dll, "CreateFileMappingNumaA");
	kernel32.oCreateFileMappingNumaW = GetProcAddress(kernel32.dll, "CreateFileMappingNumaW");
	kernel32.oCreateFileMappingW = GetProcAddress(kernel32.dll, "CreateFileMappingW");
	kernel32.oCreateFileTransactedA = GetProcAddress(kernel32.dll, "CreateFileTransactedA");
	kernel32.oCreateFileTransactedW = GetProcAddress(kernel32.dll, "CreateFileTransactedW");
	kernel32.oCreateFileW = GetProcAddress(kernel32.dll, "CreateFileW");
	kernel32.oCreateHardLinkA = GetProcAddress(kernel32.dll, "CreateHardLinkA");
	kernel32.oCreateHardLinkTransactedA = GetProcAddress(kernel32.dll, "CreateHardLinkTransactedA");
	kernel32.oCreateHardLinkTransactedW = GetProcAddress(kernel32.dll, "CreateHardLinkTransactedW");
	kernel32.oCreateHardLinkW = GetProcAddress(kernel32.dll, "CreateHardLinkW");
	kernel32.oCreateIoCompletionPort = GetProcAddress(kernel32.dll, "CreateIoCompletionPort");
	kernel32.oCreateJobObjectA = GetProcAddress(kernel32.dll, "CreateJobObjectA");
	kernel32.oCreateJobObjectW = GetProcAddress(kernel32.dll, "CreateJobObjectW");
	kernel32.oCreateJobSet = GetProcAddress(kernel32.dll, "CreateJobSet");
	kernel32.oCreateMailslotA = GetProcAddress(kernel32.dll, "CreateMailslotA");
	kernel32.oCreateMailslotW = GetProcAddress(kernel32.dll, "CreateMailslotW");
	kernel32.oCreateMemoryResourceNotification = GetProcAddress(kernel32.dll, "CreateMemoryResourceNotification");
	kernel32.oCreateMutexA = GetProcAddress(kernel32.dll, "CreateMutexA");
	kernel32.oCreateMutexExA = GetProcAddress(kernel32.dll, "CreateMutexExA");
	kernel32.oCreateMutexExW = GetProcAddress(kernel32.dll, "CreateMutexExW");
	kernel32.oCreateMutexW = GetProcAddress(kernel32.dll, "CreateMutexW");
	kernel32.oCreateNamedPipeA = GetProcAddress(kernel32.dll, "CreateNamedPipeA");
	kernel32.oCreateNamedPipeW = GetProcAddress(kernel32.dll, "CreateNamedPipeW");
	kernel32.oCreatePipe = GetProcAddress(kernel32.dll, "CreatePipe");
	kernel32.oCreatePrivateNamespaceA = GetProcAddress(kernel32.dll, "CreatePrivateNamespaceA");
	kernel32.oCreatePrivateNamespaceW = GetProcAddress(kernel32.dll, "CreatePrivateNamespaceW");
	kernel32.oCreateProcessA = GetProcAddress(kernel32.dll, "CreateProcessA");
	kernel32.oCreateProcessAsUserA = GetProcAddress(kernel32.dll, "CreateProcessAsUserA");
	kernel32.oCreateProcessAsUserW = GetProcAddress(kernel32.dll, "CreateProcessAsUserW");
	kernel32.oCreateProcessInternalA = GetProcAddress(kernel32.dll, "CreateProcessInternalA");
	kernel32.oCreateProcessInternalW = GetProcAddress(kernel32.dll, "CreateProcessInternalW");
	kernel32.oCreateProcessW = GetProcAddress(kernel32.dll, "CreateProcessW");
	kernel32.oCreatePseudoConsole = GetProcAddress(kernel32.dll, "CreatePseudoConsole");
	kernel32.oCreateRemoteThread = GetProcAddress(kernel32.dll, "CreateRemoteThread");
	kernel32.oCreateRemoteThreadEx = GetProcAddress(kernel32.dll, "CreateRemoteThreadEx");
	kernel32.oCreateSemaphoreA = GetProcAddress(kernel32.dll, "CreateSemaphoreA");
	kernel32.oCreateSemaphoreExA = GetProcAddress(kernel32.dll, "CreateSemaphoreExA");
	kernel32.oCreateSemaphoreExW = GetProcAddress(kernel32.dll, "CreateSemaphoreExW");
	kernel32.oCreateSemaphoreW = GetProcAddress(kernel32.dll, "CreateSemaphoreW");
	kernel32.oCreateSymbolicLinkA = GetProcAddress(kernel32.dll, "CreateSymbolicLinkA");
	kernel32.oCreateSymbolicLinkTransactedA = GetProcAddress(kernel32.dll, "CreateSymbolicLinkTransactedA");
	kernel32.oCreateSymbolicLinkTransactedW = GetProcAddress(kernel32.dll, "CreateSymbolicLinkTransactedW");
	kernel32.oCreateSymbolicLinkW = GetProcAddress(kernel32.dll, "CreateSymbolicLinkW");
	kernel32.oCreateTapePartition = GetProcAddress(kernel32.dll, "CreateTapePartition");
	kernel32.oCreateThread = GetProcAddress(kernel32.dll, "CreateThread");
	kernel32.oCreateThreadpool = GetProcAddress(kernel32.dll, "CreateThreadpool");
	kernel32.oCreateThreadpoolCleanupGroup = GetProcAddress(kernel32.dll, "CreateThreadpoolCleanupGroup");
	kernel32.oCreateThreadpoolIo = GetProcAddress(kernel32.dll, "CreateThreadpoolIo");
	kernel32.oCreateThreadpoolTimer = GetProcAddress(kernel32.dll, "CreateThreadpoolTimer");
	kernel32.oCreateThreadpoolWait = GetProcAddress(kernel32.dll, "CreateThreadpoolWait");
	kernel32.oCreateThreadpoolWork = GetProcAddress(kernel32.dll, "CreateThreadpoolWork");
	kernel32.oCreateTimerQueue = GetProcAddress(kernel32.dll, "CreateTimerQueue");
	kernel32.oCreateTimerQueueTimer = GetProcAddress(kernel32.dll, "CreateTimerQueueTimer");
	kernel32.oCreateToolhelp32Snapshot = GetProcAddress(kernel32.dll, "CreateToolhelp32Snapshot");
	kernel32.oCreateUmsCompletionList = GetProcAddress(kernel32.dll, "CreateUmsCompletionList");
	kernel32.oCreateUmsThreadContext = GetProcAddress(kernel32.dll, "CreateUmsThreadContext");
	kernel32.oCreateWaitableTimerA = GetProcAddress(kernel32.dll, "CreateWaitableTimerA");
	kernel32.oCreateWaitableTimerExA = GetProcAddress(kernel32.dll, "CreateWaitableTimerExA");
	kernel32.oCreateWaitableTimerExW = GetProcAddress(kernel32.dll, "CreateWaitableTimerExW");
	kernel32.oCreateWaitableTimerW = GetProcAddress(kernel32.dll, "CreateWaitableTimerW");
	kernel32.oCtrlRoutine = GetProcAddress(kernel32.dll, "CtrlRoutine");
	kernel32.oDeactivateActCtx = GetProcAddress(kernel32.dll, "DeactivateActCtx");
	kernel32.oDeactivateActCtxWorker = GetProcAddress(kernel32.dll, "DeactivateActCtxWorker");
	kernel32.oDebugActiveProcess = GetProcAddress(kernel32.dll, "DebugActiveProcess");
	kernel32.oDebugActiveProcessStop = GetProcAddress(kernel32.dll, "DebugActiveProcessStop");
	kernel32.oDebugBreak = GetProcAddress(kernel32.dll, "DebugBreak");
	kernel32.oDebugBreakProcess = GetProcAddress(kernel32.dll, "DebugBreakProcess");
	kernel32.oDebugSetProcessKillOnExit = GetProcAddress(kernel32.dll, "DebugSetProcessKillOnExit");
	kernel32.oDecodePointer = GetProcAddress(kernel32.dll, "DecodePointer");
	kernel32.oDecodeSystemPointer = GetProcAddress(kernel32.dll, "DecodeSystemPointer");
	kernel32.oDefineDosDeviceA = GetProcAddress(kernel32.dll, "DefineDosDeviceA");
	kernel32.oDefineDosDeviceW = GetProcAddress(kernel32.dll, "DefineDosDeviceW");
	kernel32.oDelayLoadFailureHook = GetProcAddress(kernel32.dll, "DelayLoadFailureHook");
	kernel32.oDeleteAtom = GetProcAddress(kernel32.dll, "DeleteAtom");
	kernel32.oDeleteBoundaryDescriptor = GetProcAddress(kernel32.dll, "DeleteBoundaryDescriptor");
	kernel32.oDeleteCriticalSection = GetProcAddress(kernel32.dll, "DeleteCriticalSection");
	kernel32.oDeleteFiber = GetProcAddress(kernel32.dll, "DeleteFiber");
	kernel32.oDeleteFileA = GetProcAddress(kernel32.dll, "DeleteFileA");
	kernel32.oDeleteFileTransactedA = GetProcAddress(kernel32.dll, "DeleteFileTransactedA");
	kernel32.oDeleteFileTransactedW = GetProcAddress(kernel32.dll, "DeleteFileTransactedW");
	kernel32.oDeleteFileW = GetProcAddress(kernel32.dll, "DeleteFileW");
	kernel32.oDeleteProcThreadAttributeList = GetProcAddress(kernel32.dll, "DeleteProcThreadAttributeList");
	kernel32.oDeleteSynchronizationBarrier = GetProcAddress(kernel32.dll, "DeleteSynchronizationBarrier");
	kernel32.oDeleteTimerQueue = GetProcAddress(kernel32.dll, "DeleteTimerQueue");
	kernel32.oDeleteTimerQueueEx = GetProcAddress(kernel32.dll, "DeleteTimerQueueEx");
	kernel32.oDeleteTimerQueueTimer = GetProcAddress(kernel32.dll, "DeleteTimerQueueTimer");
	kernel32.oDeleteUmsCompletionList = GetProcAddress(kernel32.dll, "DeleteUmsCompletionList");
	kernel32.oDeleteUmsThreadContext = GetProcAddress(kernel32.dll, "DeleteUmsThreadContext");
	kernel32.oDeleteVolumeMountPointA = GetProcAddress(kernel32.dll, "DeleteVolumeMountPointA");
	kernel32.oDeleteVolumeMountPointW = GetProcAddress(kernel32.dll, "DeleteVolumeMountPointW");
	kernel32.oDequeueUmsCompletionListItems = GetProcAddress(kernel32.dll, "DequeueUmsCompletionListItems");
	kernel32.oDeviceIoControl = GetProcAddress(kernel32.dll, "DeviceIoControl");
	kernel32.oDisableThreadLibraryCalls = GetProcAddress(kernel32.dll, "DisableThreadLibraryCalls");
	kernel32.oDisableThreadProfiling = GetProcAddress(kernel32.dll, "DisableThreadProfiling");
	kernel32.oDisassociateCurrentThreadFromCallback = GetProcAddress(kernel32.dll, "DisassociateCurrentThreadFromCallback");
	kernel32.oDiscardVirtualMemory = GetProcAddress(kernel32.dll, "DiscardVirtualMemory");
	kernel32.oDisconnectNamedPipe = GetProcAddress(kernel32.dll, "DisconnectNamedPipe");
	kernel32.oDnsHostnameToComputerNameA = GetProcAddress(kernel32.dll, "DnsHostnameToComputerNameA");
	kernel32.oDnsHostnameToComputerNameExW = GetProcAddress(kernel32.dll, "DnsHostnameToComputerNameExW");
	kernel32.oDnsHostnameToComputerNameW = GetProcAddress(kernel32.dll, "DnsHostnameToComputerNameW");
	kernel32.oDosDateTimeToFileTime = GetProcAddress(kernel32.dll, "DosDateTimeToFileTime");
	kernel32.oDosPathToSessionPathA = GetProcAddress(kernel32.dll, "DosPathToSessionPathA");
	kernel32.oDosPathToSessionPathW = GetProcAddress(kernel32.dll, "DosPathToSessionPathW");
	kernel32.oDuplicateConsoleHandle = GetProcAddress(kernel32.dll, "DuplicateConsoleHandle");
	kernel32.oDuplicateEncryptionInfoFileExt = GetProcAddress(kernel32.dll, "DuplicateEncryptionInfoFileExt");
	kernel32.oDuplicateHandle = GetProcAddress(kernel32.dll, "DuplicateHandle");
	kernel32.oEnableThreadProfiling = GetProcAddress(kernel32.dll, "EnableThreadProfiling");
	kernel32.oEncodePointer = GetProcAddress(kernel32.dll, "EncodePointer");
	kernel32.oEncodeSystemPointer = GetProcAddress(kernel32.dll, "EncodeSystemPointer");
	kernel32.oEndUpdateResourceA = GetProcAddress(kernel32.dll, "EndUpdateResourceA");
	kernel32.oEndUpdateResourceW = GetProcAddress(kernel32.dll, "EndUpdateResourceW");
	kernel32.oEnterCriticalSection = GetProcAddress(kernel32.dll, "EnterCriticalSection");
	kernel32.oEnterSynchronizationBarrier = GetProcAddress(kernel32.dll, "EnterSynchronizationBarrier");
	kernel32.oEnterUmsSchedulingMode = GetProcAddress(kernel32.dll, "EnterUmsSchedulingMode");
	kernel32.oEnumCalendarInfoA = GetProcAddress(kernel32.dll, "EnumCalendarInfoA");
	kernel32.oEnumCalendarInfoExA = GetProcAddress(kernel32.dll, "EnumCalendarInfoExA");
	kernel32.oEnumCalendarInfoExEx = GetProcAddress(kernel32.dll, "EnumCalendarInfoExEx");
	kernel32.oEnumCalendarInfoExW = GetProcAddress(kernel32.dll, "EnumCalendarInfoExW");
	kernel32.oEnumCalendarInfoW = GetProcAddress(kernel32.dll, "EnumCalendarInfoW");
	kernel32.oEnumDateFormatsA = GetProcAddress(kernel32.dll, "EnumDateFormatsA");
	kernel32.oEnumDateFormatsExA = GetProcAddress(kernel32.dll, "EnumDateFormatsExA");
	kernel32.oEnumDateFormatsExEx = GetProcAddress(kernel32.dll, "EnumDateFormatsExEx");
	kernel32.oEnumDateFormatsExW = GetProcAddress(kernel32.dll, "EnumDateFormatsExW");
	kernel32.oEnumDateFormatsW = GetProcAddress(kernel32.dll, "EnumDateFormatsW");
	kernel32.oEnumLanguageGroupLocalesA = GetProcAddress(kernel32.dll, "EnumLanguageGroupLocalesA");
	kernel32.oEnumLanguageGroupLocalesW = GetProcAddress(kernel32.dll, "EnumLanguageGroupLocalesW");
	kernel32.oEnumResourceLanguagesA = GetProcAddress(kernel32.dll, "EnumResourceLanguagesA");
	kernel32.oEnumResourceLanguagesExA = GetProcAddress(kernel32.dll, "EnumResourceLanguagesExA");
	kernel32.oEnumResourceLanguagesExW = GetProcAddress(kernel32.dll, "EnumResourceLanguagesExW");
	kernel32.oEnumResourceLanguagesW = GetProcAddress(kernel32.dll, "EnumResourceLanguagesW");
	kernel32.oEnumResourceNamesA = GetProcAddress(kernel32.dll, "EnumResourceNamesA");
	kernel32.oEnumResourceNamesExA = GetProcAddress(kernel32.dll, "EnumResourceNamesExA");
	kernel32.oEnumResourceNamesExW = GetProcAddress(kernel32.dll, "EnumResourceNamesExW");
	kernel32.oEnumResourceNamesW = GetProcAddress(kernel32.dll, "EnumResourceNamesW");
	kernel32.oEnumResourceTypesA = GetProcAddress(kernel32.dll, "EnumResourceTypesA");
	kernel32.oEnumResourceTypesExA = GetProcAddress(kernel32.dll, "EnumResourceTypesExA");
	kernel32.oEnumResourceTypesExW = GetProcAddress(kernel32.dll, "EnumResourceTypesExW");
	kernel32.oEnumResourceTypesW = GetProcAddress(kernel32.dll, "EnumResourceTypesW");
	kernel32.oEnumSystemCodePagesA = GetProcAddress(kernel32.dll, "EnumSystemCodePagesA");
	kernel32.oEnumSystemCodePagesW = GetProcAddress(kernel32.dll, "EnumSystemCodePagesW");
	kernel32.oEnumSystemFirmwareTables = GetProcAddress(kernel32.dll, "EnumSystemFirmwareTables");
	kernel32.oEnumSystemGeoID = GetProcAddress(kernel32.dll, "EnumSystemGeoID");
	kernel32.oEnumSystemGeoNames = GetProcAddress(kernel32.dll, "EnumSystemGeoNames");
	kernel32.oEnumSystemLanguageGroupsA = GetProcAddress(kernel32.dll, "EnumSystemLanguageGroupsA");
	kernel32.oEnumSystemLanguageGroupsW = GetProcAddress(kernel32.dll, "EnumSystemLanguageGroupsW");
	kernel32.oEnumSystemLocalesA = GetProcAddress(kernel32.dll, "EnumSystemLocalesA");
	kernel32.oEnumSystemLocalesEx = GetProcAddress(kernel32.dll, "EnumSystemLocalesEx");
	kernel32.oEnumSystemLocalesW = GetProcAddress(kernel32.dll, "EnumSystemLocalesW");
	kernel32.oEnumTimeFormatsA = GetProcAddress(kernel32.dll, "EnumTimeFormatsA");
	kernel32.oEnumTimeFormatsEx = GetProcAddress(kernel32.dll, "EnumTimeFormatsEx");
	kernel32.oEnumTimeFormatsW = GetProcAddress(kernel32.dll, "EnumTimeFormatsW");
	kernel32.oEnumUILanguagesA = GetProcAddress(kernel32.dll, "EnumUILanguagesA");
	kernel32.oEnumUILanguagesW = GetProcAddress(kernel32.dll, "EnumUILanguagesW");
	kernel32.oEnumerateLocalComputerNamesA = GetProcAddress(kernel32.dll, "EnumerateLocalComputerNamesA");
	kernel32.oEnumerateLocalComputerNamesW = GetProcAddress(kernel32.dll, "EnumerateLocalComputerNamesW");
	kernel32.oEraseTape = GetProcAddress(kernel32.dll, "EraseTape");
	kernel32.oEscapeCommFunction = GetProcAddress(kernel32.dll, "EscapeCommFunction");
	kernel32.oExecuteUmsThread = GetProcAddress(kernel32.dll, "ExecuteUmsThread");
	kernel32.oExitProcess = GetProcAddress(kernel32.dll, "ExitProcess");
	kernel32.oExitThread = GetProcAddress(kernel32.dll, "ExitThread");
	kernel32.oExitVDM = GetProcAddress(kernel32.dll, "ExitVDM");
	kernel32.oExpandEnvironmentStringsA = GetProcAddress(kernel32.dll, "ExpandEnvironmentStringsA");
	kernel32.oExpandEnvironmentStringsW = GetProcAddress(kernel32.dll, "ExpandEnvironmentStringsW");
	kernel32.oExpungeConsoleCommandHistoryA = GetProcAddress(kernel32.dll, "ExpungeConsoleCommandHistoryA");
	kernel32.oExpungeConsoleCommandHistoryW = GetProcAddress(kernel32.dll, "ExpungeConsoleCommandHistoryW");
	kernel32.oFatalAppExitA = GetProcAddress(kernel32.dll, "FatalAppExitA");
	kernel32.oFatalAppExitW = GetProcAddress(kernel32.dll, "FatalAppExitW");
	kernel32.oFatalExit = GetProcAddress(kernel32.dll, "FatalExit");
	kernel32.oFileTimeToDosDateTime = GetProcAddress(kernel32.dll, "FileTimeToDosDateTime");
	kernel32.oFileTimeToLocalFileTime = GetProcAddress(kernel32.dll, "FileTimeToLocalFileTime");
	kernel32.oFileTimeToSystemTime = GetProcAddress(kernel32.dll, "FileTimeToSystemTime");
	kernel32.oFillConsoleOutputAttribute = GetProcAddress(kernel32.dll, "FillConsoleOutputAttribute");
	kernel32.oFillConsoleOutputCharacterA = GetProcAddress(kernel32.dll, "FillConsoleOutputCharacterA");
	kernel32.oFillConsoleOutputCharacterW = GetProcAddress(kernel32.dll, "FillConsoleOutputCharacterW");
	kernel32.oFindActCtxSectionGuid = GetProcAddress(kernel32.dll, "FindActCtxSectionGuid");
	kernel32.oFindActCtxSectionGuidWorker = GetProcAddress(kernel32.dll, "FindActCtxSectionGuidWorker");
	kernel32.oFindActCtxSectionStringA = GetProcAddress(kernel32.dll, "FindActCtxSectionStringA");
	kernel32.oFindActCtxSectionStringW = GetProcAddress(kernel32.dll, "FindActCtxSectionStringW");
	kernel32.oFindActCtxSectionStringWWorker = GetProcAddress(kernel32.dll, "FindActCtxSectionStringWWorker");
	kernel32.oFindAtomA = GetProcAddress(kernel32.dll, "FindAtomA");
	kernel32.oFindAtomW = GetProcAddress(kernel32.dll, "FindAtomW");
	kernel32.oFindClose = GetProcAddress(kernel32.dll, "FindClose");
	kernel32.oFindCloseChangeNotification = GetProcAddress(kernel32.dll, "FindCloseChangeNotification");
	kernel32.oFindFirstChangeNotificationA = GetProcAddress(kernel32.dll, "FindFirstChangeNotificationA");
	kernel32.oFindFirstChangeNotificationW = GetProcAddress(kernel32.dll, "FindFirstChangeNotificationW");
	kernel32.oFindFirstFileA = GetProcAddress(kernel32.dll, "FindFirstFileA");
	kernel32.oFindFirstFileExA = GetProcAddress(kernel32.dll, "FindFirstFileExA");
	kernel32.oFindFirstFileExW = GetProcAddress(kernel32.dll, "FindFirstFileExW");
	kernel32.oFindFirstFileNameTransactedW = GetProcAddress(kernel32.dll, "FindFirstFileNameTransactedW");
	kernel32.oFindFirstFileNameW = GetProcAddress(kernel32.dll, "FindFirstFileNameW");
	kernel32.oFindFirstFileTransactedA = GetProcAddress(kernel32.dll, "FindFirstFileTransactedA");
	kernel32.oFindFirstFileTransactedW = GetProcAddress(kernel32.dll, "FindFirstFileTransactedW");
	kernel32.oFindFirstFileW = GetProcAddress(kernel32.dll, "FindFirstFileW");
	kernel32.oFindFirstStreamTransactedW = GetProcAddress(kernel32.dll, "FindFirstStreamTransactedW");
	kernel32.oFindFirstStreamW = GetProcAddress(kernel32.dll, "FindFirstStreamW");
	kernel32.oFindFirstVolumeA = GetProcAddress(kernel32.dll, "FindFirstVolumeA");
	kernel32.oFindFirstVolumeMountPointA = GetProcAddress(kernel32.dll, "FindFirstVolumeMountPointA");
	kernel32.oFindFirstVolumeMountPointW = GetProcAddress(kernel32.dll, "FindFirstVolumeMountPointW");
	kernel32.oFindFirstVolumeW = GetProcAddress(kernel32.dll, "FindFirstVolumeW");
	kernel32.oFindNLSString = GetProcAddress(kernel32.dll, "FindNLSString");
	kernel32.oFindNLSStringEx = GetProcAddress(kernel32.dll, "FindNLSStringEx");
	kernel32.oFindNextChangeNotification = GetProcAddress(kernel32.dll, "FindNextChangeNotification");
	kernel32.oFindNextFileA = GetProcAddress(kernel32.dll, "FindNextFileA");
	kernel32.oFindNextFileNameW = GetProcAddress(kernel32.dll, "FindNextFileNameW");
	kernel32.oFindNextFileW = GetProcAddress(kernel32.dll, "FindNextFileW");
	kernel32.oFindNextStreamW = GetProcAddress(kernel32.dll, "FindNextStreamW");
	kernel32.oFindNextVolumeA = GetProcAddress(kernel32.dll, "FindNextVolumeA");
	kernel32.oFindNextVolumeMountPointA = GetProcAddress(kernel32.dll, "FindNextVolumeMountPointA");
	kernel32.oFindNextVolumeMountPointW = GetProcAddress(kernel32.dll, "FindNextVolumeMountPointW");
	kernel32.oFindNextVolumeW = GetProcAddress(kernel32.dll, "FindNextVolumeW");
	kernel32.oFindPackagesByPackageFamily = GetProcAddress(kernel32.dll, "FindPackagesByPackageFamily");
	kernel32.oFindResourceA = GetProcAddress(kernel32.dll, "FindResourceA");
	kernel32.oFindResourceExA = GetProcAddress(kernel32.dll, "FindResourceExA");
	kernel32.oFindResourceExW = GetProcAddress(kernel32.dll, "FindResourceExW");
	kernel32.oFindResourceW = GetProcAddress(kernel32.dll, "FindResourceW");
	kernel32.oFindStringOrdinal = GetProcAddress(kernel32.dll, "FindStringOrdinal");
	kernel32.oFindVolumeClose = GetProcAddress(kernel32.dll, "FindVolumeClose");
	kernel32.oFindVolumeMountPointClose = GetProcAddress(kernel32.dll, "FindVolumeMountPointClose");
	kernel32.oFlsAlloc = GetProcAddress(kernel32.dll, "FlsAlloc");
	kernel32.oFlsFree = GetProcAddress(kernel32.dll, "FlsFree");
	kernel32.oFlsGetValue = GetProcAddress(kernel32.dll, "FlsGetValue");
	kernel32.oFlsSetValue = GetProcAddress(kernel32.dll, "FlsSetValue");
	kernel32.oFlushConsoleInputBuffer = GetProcAddress(kernel32.dll, "FlushConsoleInputBuffer");
	kernel32.oFlushFileBuffers = GetProcAddress(kernel32.dll, "FlushFileBuffers");
	kernel32.oFlushInstructionCache = GetProcAddress(kernel32.dll, "FlushInstructionCache");
	kernel32.oFlushProcessWriteBuffers = GetProcAddress(kernel32.dll, "FlushProcessWriteBuffers");
	kernel32.oFlushViewOfFile = GetProcAddress(kernel32.dll, "FlushViewOfFile");
	kernel32.oFoldStringA = GetProcAddress(kernel32.dll, "FoldStringA");
	kernel32.oFoldStringW = GetProcAddress(kernel32.dll, "FoldStringW");
	kernel32.oFormatApplicationUserModelId = GetProcAddress(kernel32.dll, "FormatApplicationUserModelId");
	kernel32.oFormatMessageA = GetProcAddress(kernel32.dll, "FormatMessageA");
	kernel32.oFormatMessageW = GetProcAddress(kernel32.dll, "FormatMessageW");
	kernel32.oFreeConsole = GetProcAddress(kernel32.dll, "FreeConsole");
	kernel32.oFreeEnvironmentStringsA = GetProcAddress(kernel32.dll, "FreeEnvironmentStringsA");
	kernel32.oFreeEnvironmentStringsW = GetProcAddress(kernel32.dll, "FreeEnvironmentStringsW");
	kernel32.oFreeLibrary = GetProcAddress(kernel32.dll, "FreeLibrary");
	kernel32.oFreeLibraryAndExitThread = GetProcAddress(kernel32.dll, "FreeLibraryAndExitThread");
	kernel32.oFreeLibraryWhenCallbackReturns = GetProcAddress(kernel32.dll, "FreeLibraryWhenCallbackReturns");
	kernel32.oFreeMemoryJobObject = GetProcAddress(kernel32.dll, "FreeMemoryJobObject");
	kernel32.oFreeResource = GetProcAddress(kernel32.dll, "FreeResource");
	kernel32.oFreeUserPhysicalPages = GetProcAddress(kernel32.dll, "FreeUserPhysicalPages");
	kernel32.oGenerateConsoleCtrlEvent = GetProcAddress(kernel32.dll, "GenerateConsoleCtrlEvent");
	kernel32.oGetACP = GetProcAddress(kernel32.dll, "GetACP");
	kernel32.oGetActiveProcessorCount = GetProcAddress(kernel32.dll, "GetActiveProcessorCount");
	kernel32.oGetActiveProcessorGroupCount = GetProcAddress(kernel32.dll, "GetActiveProcessorGroupCount");
	kernel32.oGetAppContainerAce = GetProcAddress(kernel32.dll, "GetAppContainerAce");
	kernel32.oGetAppContainerNamedObjectPath = GetProcAddress(kernel32.dll, "GetAppContainerNamedObjectPath");
	kernel32.oGetApplicationRecoveryCallback = GetProcAddress(kernel32.dll, "GetApplicationRecoveryCallback");
	kernel32.oGetApplicationRecoveryCallbackWorker = GetProcAddress(kernel32.dll, "GetApplicationRecoveryCallbackWorker");
	kernel32.oGetApplicationRestartSettings = GetProcAddress(kernel32.dll, "GetApplicationRestartSettings");
	kernel32.oGetApplicationRestartSettingsWorker = GetProcAddress(kernel32.dll, "GetApplicationRestartSettingsWorker");
	kernel32.oGetApplicationUserModelId = GetProcAddress(kernel32.dll, "GetApplicationUserModelId");
	kernel32.oGetAtomNameA = GetProcAddress(kernel32.dll, "GetAtomNameA");
	kernel32.oGetAtomNameW = GetProcAddress(kernel32.dll, "GetAtomNameW");
	kernel32.oGetBinaryType = GetProcAddress(kernel32.dll, "GetBinaryType");
	kernel32.oGetBinaryTypeA = GetProcAddress(kernel32.dll, "GetBinaryTypeA");
	kernel32.oGetBinaryTypeW = GetProcAddress(kernel32.dll, "GetBinaryTypeW");
	kernel32.oGetCPInfo = GetProcAddress(kernel32.dll, "GetCPInfo");
	kernel32.oGetCPInfoExA = GetProcAddress(kernel32.dll, "GetCPInfoExA");
	kernel32.oGetCPInfoExW = GetProcAddress(kernel32.dll, "GetCPInfoExW");
	kernel32.oGetCachedSigningLevel = GetProcAddress(kernel32.dll, "GetCachedSigningLevel");
	kernel32.oGetCalendarDateFormat = GetProcAddress(kernel32.dll, "GetCalendarDateFormat");
	kernel32.oGetCalendarDateFormatEx = GetProcAddress(kernel32.dll, "GetCalendarDateFormatEx");
	kernel32.oGetCalendarDaysInMonth = GetProcAddress(kernel32.dll, "GetCalendarDaysInMonth");
	kernel32.oGetCalendarDifferenceInDays = GetProcAddress(kernel32.dll, "GetCalendarDifferenceInDays");
	kernel32.oGetCalendarInfoA = GetProcAddress(kernel32.dll, "GetCalendarInfoA");
	kernel32.oGetCalendarInfoEx = GetProcAddress(kernel32.dll, "GetCalendarInfoEx");
	kernel32.oGetCalendarInfoW = GetProcAddress(kernel32.dll, "GetCalendarInfoW");
	kernel32.oGetCalendarMonthsInYear = GetProcAddress(kernel32.dll, "GetCalendarMonthsInYear");
	kernel32.oGetCalendarSupportedDateRange = GetProcAddress(kernel32.dll, "GetCalendarSupportedDateRange");
	kernel32.oGetCalendarWeekNumber = GetProcAddress(kernel32.dll, "GetCalendarWeekNumber");
	kernel32.oGetComPlusPackageInstallStatus = GetProcAddress(kernel32.dll, "GetComPlusPackageInstallStatus");
	kernel32.oGetCommConfig = GetProcAddress(kernel32.dll, "GetCommConfig");
	kernel32.oGetCommMask = GetProcAddress(kernel32.dll, "GetCommMask");
	kernel32.oGetCommModemStatus = GetProcAddress(kernel32.dll, "GetCommModemStatus");
	kernel32.oGetCommProperties = GetProcAddress(kernel32.dll, "GetCommProperties");
	kernel32.oGetCommState = GetProcAddress(kernel32.dll, "GetCommState");
	kernel32.oGetCommTimeouts = GetProcAddress(kernel32.dll, "GetCommTimeouts");
	kernel32.oGetCommandLineA = GetProcAddress(kernel32.dll, "GetCommandLineA");
	kernel32.oGetCommandLineW = GetProcAddress(kernel32.dll, "GetCommandLineW");
	kernel32.oGetCompressedFileSizeA = GetProcAddress(kernel32.dll, "GetCompressedFileSizeA");
	kernel32.oGetCompressedFileSizeTransactedA = GetProcAddress(kernel32.dll, "GetCompressedFileSizeTransactedA");
	kernel32.oGetCompressedFileSizeTransactedW = GetProcAddress(kernel32.dll, "GetCompressedFileSizeTransactedW");
	kernel32.oGetCompressedFileSizeW = GetProcAddress(kernel32.dll, "GetCompressedFileSizeW");
	kernel32.oGetComputerNameA = GetProcAddress(kernel32.dll, "GetComputerNameA");
	kernel32.oGetComputerNameExA = GetProcAddress(kernel32.dll, "GetComputerNameExA");
	kernel32.oGetComputerNameExW = GetProcAddress(kernel32.dll, "GetComputerNameExW");
	kernel32.oGetComputerNameW = GetProcAddress(kernel32.dll, "GetComputerNameW");
	kernel32.oGetConsoleAliasA = GetProcAddress(kernel32.dll, "GetConsoleAliasA");
	kernel32.oGetConsoleAliasExesA = GetProcAddress(kernel32.dll, "GetConsoleAliasExesA");
	kernel32.oGetConsoleAliasExesLengthA = GetProcAddress(kernel32.dll, "GetConsoleAliasExesLengthA");
	kernel32.oGetConsoleAliasExesLengthW = GetProcAddress(kernel32.dll, "GetConsoleAliasExesLengthW");
	kernel32.oGetConsoleAliasExesW = GetProcAddress(kernel32.dll, "GetConsoleAliasExesW");
	kernel32.oGetConsoleAliasW = GetProcAddress(kernel32.dll, "GetConsoleAliasW");
	kernel32.oGetConsoleAliasesA = GetProcAddress(kernel32.dll, "GetConsoleAliasesA");
	kernel32.oGetConsoleAliasesLengthA = GetProcAddress(kernel32.dll, "GetConsoleAliasesLengthA");
	kernel32.oGetConsoleAliasesLengthW = GetProcAddress(kernel32.dll, "GetConsoleAliasesLengthW");
	kernel32.oGetConsoleAliasesW = GetProcAddress(kernel32.dll, "GetConsoleAliasesW");
	kernel32.oGetConsoleCP = GetProcAddress(kernel32.dll, "GetConsoleCP");
	kernel32.oGetConsoleCharType = GetProcAddress(kernel32.dll, "GetConsoleCharType");
	kernel32.oGetConsoleCommandHistoryA = GetProcAddress(kernel32.dll, "GetConsoleCommandHistoryA");
	kernel32.oGetConsoleCommandHistoryLengthA = GetProcAddress(kernel32.dll, "GetConsoleCommandHistoryLengthA");
	kernel32.oGetConsoleCommandHistoryLengthW = GetProcAddress(kernel32.dll, "GetConsoleCommandHistoryLengthW");
	kernel32.oGetConsoleCommandHistoryW = GetProcAddress(kernel32.dll, "GetConsoleCommandHistoryW");
	kernel32.oGetConsoleCursorInfo = GetProcAddress(kernel32.dll, "GetConsoleCursorInfo");
	kernel32.oGetConsoleCursorMode = GetProcAddress(kernel32.dll, "GetConsoleCursorMode");
	kernel32.oGetConsoleDisplayMode = GetProcAddress(kernel32.dll, "GetConsoleDisplayMode");
	kernel32.oGetConsoleFontInfo = GetProcAddress(kernel32.dll, "GetConsoleFontInfo");
	kernel32.oGetConsoleFontSize = GetProcAddress(kernel32.dll, "GetConsoleFontSize");
	kernel32.oGetConsoleHardwareState = GetProcAddress(kernel32.dll, "GetConsoleHardwareState");
	kernel32.oGetConsoleHistoryInfo = GetProcAddress(kernel32.dll, "GetConsoleHistoryInfo");
	kernel32.oGetConsoleInputExeNameA = GetProcAddress(kernel32.dll, "GetConsoleInputExeNameA");
	kernel32.oGetConsoleInputExeNameW = GetProcAddress(kernel32.dll, "GetConsoleInputExeNameW");
	kernel32.oGetConsoleInputWaitHandle = GetProcAddress(kernel32.dll, "GetConsoleInputWaitHandle");
	kernel32.oGetConsoleKeyboardLayoutNameA = GetProcAddress(kernel32.dll, "GetConsoleKeyboardLayoutNameA");
	kernel32.oGetConsoleKeyboardLayoutNameW = GetProcAddress(kernel32.dll, "GetConsoleKeyboardLayoutNameW");
	kernel32.oGetConsoleMode = GetProcAddress(kernel32.dll, "GetConsoleMode");
	kernel32.oGetConsoleNlsMode = GetProcAddress(kernel32.dll, "GetConsoleNlsMode");
	kernel32.oGetConsoleOriginalTitleA = GetProcAddress(kernel32.dll, "GetConsoleOriginalTitleA");
	kernel32.oGetConsoleOriginalTitleW = GetProcAddress(kernel32.dll, "GetConsoleOriginalTitleW");
	kernel32.oGetConsoleOutputCP = GetProcAddress(kernel32.dll, "GetConsoleOutputCP");
	kernel32.oGetConsoleProcessList = GetProcAddress(kernel32.dll, "GetConsoleProcessList");
	kernel32.oGetConsoleScreenBufferInfo = GetProcAddress(kernel32.dll, "GetConsoleScreenBufferInfo");
	kernel32.oGetConsoleScreenBufferInfoEx = GetProcAddress(kernel32.dll, "GetConsoleScreenBufferInfoEx");
	kernel32.oGetConsoleSelectionInfo = GetProcAddress(kernel32.dll, "GetConsoleSelectionInfo");
	kernel32.oGetConsoleTitleA = GetProcAddress(kernel32.dll, "GetConsoleTitleA");
	kernel32.oGetConsoleTitleW = GetProcAddress(kernel32.dll, "GetConsoleTitleW");
	kernel32.oGetConsoleWindow = GetProcAddress(kernel32.dll, "GetConsoleWindow");
	kernel32.oGetCurrencyFormatA = GetProcAddress(kernel32.dll, "GetCurrencyFormatA");
	kernel32.oGetCurrencyFormatEx = GetProcAddress(kernel32.dll, "GetCurrencyFormatEx");
	kernel32.oGetCurrencyFormatW = GetProcAddress(kernel32.dll, "GetCurrencyFormatW");
	kernel32.oGetCurrentActCtx = GetProcAddress(kernel32.dll, "GetCurrentActCtx");
	kernel32.oGetCurrentActCtxWorker = GetProcAddress(kernel32.dll, "GetCurrentActCtxWorker");
	kernel32.oGetCurrentApplicationUserModelId = GetProcAddress(kernel32.dll, "GetCurrentApplicationUserModelId");
	kernel32.oGetCurrentConsoleFont = GetProcAddress(kernel32.dll, "GetCurrentConsoleFont");
	kernel32.oGetCurrentConsoleFontEx = GetProcAddress(kernel32.dll, "GetCurrentConsoleFontEx");
	kernel32.oGetCurrentDirectoryA = GetProcAddress(kernel32.dll, "GetCurrentDirectoryA");
	kernel32.oGetCurrentDirectoryW = GetProcAddress(kernel32.dll, "GetCurrentDirectoryW");
	kernel32.oGetCurrentPackageFamilyName = GetProcAddress(kernel32.dll, "GetCurrentPackageFamilyName");
	kernel32.oGetCurrentPackageFullName = GetProcAddress(kernel32.dll, "GetCurrentPackageFullName");
	kernel32.oGetCurrentPackageId = GetProcAddress(kernel32.dll, "GetCurrentPackageId");
	kernel32.oGetCurrentPackageInfo = GetProcAddress(kernel32.dll, "GetCurrentPackageInfo");
	kernel32.oGetCurrentPackagePath = GetProcAddress(kernel32.dll, "GetCurrentPackagePath");
	kernel32.oGetCurrentProcess = GetProcAddress(kernel32.dll, "GetCurrentProcess");
	kernel32.oGetCurrentProcessId = GetProcAddress(kernel32.dll, "GetCurrentProcessId");
	kernel32.oGetCurrentProcessorNumber = GetProcAddress(kernel32.dll, "GetCurrentProcessorNumber");
	kernel32.oGetCurrentProcessorNumberEx = GetProcAddress(kernel32.dll, "GetCurrentProcessorNumberEx");
	kernel32.oGetCurrentThread = GetProcAddress(kernel32.dll, "GetCurrentThread");
	kernel32.oGetCurrentThreadId = GetProcAddress(kernel32.dll, "GetCurrentThreadId");
	kernel32.oGetCurrentThreadStackLimits = GetProcAddress(kernel32.dll, "GetCurrentThreadStackLimits");
	kernel32.oGetCurrentUmsThread = GetProcAddress(kernel32.dll, "GetCurrentUmsThread");
	kernel32.oGetDateFormatA = GetProcAddress(kernel32.dll, "GetDateFormatA");
	kernel32.oGetDateFormatAWorker = GetProcAddress(kernel32.dll, "GetDateFormatAWorker");
	kernel32.oGetDateFormatEx = GetProcAddress(kernel32.dll, "GetDateFormatEx");
	kernel32.oGetDateFormatW = GetProcAddress(kernel32.dll, "GetDateFormatW");
	kernel32.oGetDateFormatWWorker = GetProcAddress(kernel32.dll, "GetDateFormatWWorker");
	kernel32.oGetDefaultCommConfigA = GetProcAddress(kernel32.dll, "GetDefaultCommConfigA");
	kernel32.oGetDefaultCommConfigW = GetProcAddress(kernel32.dll, "GetDefaultCommConfigW");
	kernel32.oGetDevicePowerState = GetProcAddress(kernel32.dll, "GetDevicePowerState");
	kernel32.oGetDiskFreeSpaceA = GetProcAddress(kernel32.dll, "GetDiskFreeSpaceA");
	kernel32.oGetDiskFreeSpaceExA = GetProcAddress(kernel32.dll, "GetDiskFreeSpaceExA");
	kernel32.oGetDiskFreeSpaceExW = GetProcAddress(kernel32.dll, "GetDiskFreeSpaceExW");
	kernel32.oGetDiskFreeSpaceW = GetProcAddress(kernel32.dll, "GetDiskFreeSpaceW");
	kernel32.oGetDiskSpaceInformationA = GetProcAddress(kernel32.dll, "GetDiskSpaceInformationA");
	kernel32.oGetDiskSpaceInformationW = GetProcAddress(kernel32.dll, "GetDiskSpaceInformationW");
	kernel32.oGetDllDirectoryA = GetProcAddress(kernel32.dll, "GetDllDirectoryA");
	kernel32.oGetDllDirectoryW = GetProcAddress(kernel32.dll, "GetDllDirectoryW");
	kernel32.oGetDriveTypeA = GetProcAddress(kernel32.dll, "GetDriveTypeA");
	kernel32.oGetDriveTypeW = GetProcAddress(kernel32.dll, "GetDriveTypeW");
	kernel32.oGetDurationFormat = GetProcAddress(kernel32.dll, "GetDurationFormat");
	kernel32.oGetDurationFormatEx = GetProcAddress(kernel32.dll, "GetDurationFormatEx");
	kernel32.oGetDynamicTimeZoneInformation = GetProcAddress(kernel32.dll, "GetDynamicTimeZoneInformation");
	kernel32.oGetEnabledXStateFeatures = GetProcAddress(kernel32.dll, "GetEnabledXStateFeatures");
	kernel32.oGetEncryptedFileVersionExt = GetProcAddress(kernel32.dll, "GetEncryptedFileVersionExt");
	kernel32.oGetEnvironmentStrings = GetProcAddress(kernel32.dll, "GetEnvironmentStrings");
	kernel32.oGetEnvironmentStringsA = GetProcAddress(kernel32.dll, "GetEnvironmentStringsA");
	kernel32.oGetEnvironmentStringsW = GetProcAddress(kernel32.dll, "GetEnvironmentStringsW");
	kernel32.oGetEnvironmentVariableA = GetProcAddress(kernel32.dll, "GetEnvironmentVariableA");
	kernel32.oGetEnvironmentVariableW = GetProcAddress(kernel32.dll, "GetEnvironmentVariableW");
	kernel32.oGetEraNameCountedString = GetProcAddress(kernel32.dll, "GetEraNameCountedString");
	kernel32.oGetErrorMode = GetProcAddress(kernel32.dll, "GetErrorMode");
	kernel32.oGetExitCodeProcess = GetProcAddress(kernel32.dll, "GetExitCodeProcess");
	kernel32.oGetExitCodeThread = GetProcAddress(kernel32.dll, "GetExitCodeThread");
	kernel32.oGetExpandedNameA = GetProcAddress(kernel32.dll, "GetExpandedNameA");
	kernel32.oGetExpandedNameW = GetProcAddress(kernel32.dll, "GetExpandedNameW");
	kernel32.oGetFileAttributesA = GetProcAddress(kernel32.dll, "GetFileAttributesA");
	kernel32.oGetFileAttributesExA = GetProcAddress(kernel32.dll, "GetFileAttributesExA");
	kernel32.oGetFileAttributesExW = GetProcAddress(kernel32.dll, "GetFileAttributesExW");
	kernel32.oGetFileAttributesTransactedA = GetProcAddress(kernel32.dll, "GetFileAttributesTransactedA");
	kernel32.oGetFileAttributesTransactedW = GetProcAddress(kernel32.dll, "GetFileAttributesTransactedW");
	kernel32.oGetFileAttributesW = GetProcAddress(kernel32.dll, "GetFileAttributesW");
	kernel32.oGetFileBandwidthReservation = GetProcAddress(kernel32.dll, "GetFileBandwidthReservation");
	kernel32.oGetFileInformationByHandle = GetProcAddress(kernel32.dll, "GetFileInformationByHandle");
	kernel32.oGetFileInformationByHandleEx = GetProcAddress(kernel32.dll, "GetFileInformationByHandleEx");
	kernel32.oGetFileMUIInfo = GetProcAddress(kernel32.dll, "GetFileMUIInfo");
	kernel32.oGetFileMUIPath = GetProcAddress(kernel32.dll, "GetFileMUIPath");
	kernel32.oGetFileSize = GetProcAddress(kernel32.dll, "GetFileSize");
	kernel32.oGetFileSizeEx = GetProcAddress(kernel32.dll, "GetFileSizeEx");
	kernel32.oGetFileTime = GetProcAddress(kernel32.dll, "GetFileTime");
	kernel32.oGetFileType = GetProcAddress(kernel32.dll, "GetFileType");
	kernel32.oGetFinalPathNameByHandleA = GetProcAddress(kernel32.dll, "GetFinalPathNameByHandleA");
	kernel32.oGetFinalPathNameByHandleW = GetProcAddress(kernel32.dll, "GetFinalPathNameByHandleW");
	kernel32.oGetFirmwareEnvironmentVariableA = GetProcAddress(kernel32.dll, "GetFirmwareEnvironmentVariableA");
	kernel32.oGetFirmwareEnvironmentVariableExA = GetProcAddress(kernel32.dll, "GetFirmwareEnvironmentVariableExA");
	kernel32.oGetFirmwareEnvironmentVariableExW = GetProcAddress(kernel32.dll, "GetFirmwareEnvironmentVariableExW");
	kernel32.oGetFirmwareEnvironmentVariableW = GetProcAddress(kernel32.dll, "GetFirmwareEnvironmentVariableW");
	kernel32.oGetFirmwareType = GetProcAddress(kernel32.dll, "GetFirmwareType");
	kernel32.oGetFullPathNameA = GetProcAddress(kernel32.dll, "GetFullPathNameA");
	kernel32.oGetFullPathNameTransactedA = GetProcAddress(kernel32.dll, "GetFullPathNameTransactedA");
	kernel32.oGetFullPathNameTransactedW = GetProcAddress(kernel32.dll, "GetFullPathNameTransactedW");
	kernel32.oGetFullPathNameW = GetProcAddress(kernel32.dll, "GetFullPathNameW");
	kernel32.oGetGeoInfoA = GetProcAddress(kernel32.dll, "GetGeoInfoA");
	kernel32.oGetGeoInfoEx = GetProcAddress(kernel32.dll, "GetGeoInfoEx");
	kernel32.oGetGeoInfoW = GetProcAddress(kernel32.dll, "GetGeoInfoW");
	kernel32.oGetHandleInformation = GetProcAddress(kernel32.dll, "GetHandleInformation");
	kernel32.oGetLargePageMinimum = GetProcAddress(kernel32.dll, "GetLargePageMinimum");
	kernel32.oGetLargestConsoleWindowSize = GetProcAddress(kernel32.dll, "GetLargestConsoleWindowSize");
	kernel32.oGetLastError = GetProcAddress(kernel32.dll, "GetLastError");
	kernel32.oGetLocalTime = GetProcAddress(kernel32.dll, "GetLocalTime");
	kernel32.oGetLocaleInfoA = GetProcAddress(kernel32.dll, "GetLocaleInfoA");
	kernel32.oGetLocaleInfoEx = GetProcAddress(kernel32.dll, "GetLocaleInfoEx");
	kernel32.oGetLocaleInfoW = GetProcAddress(kernel32.dll, "GetLocaleInfoW");
	kernel32.oGetLogicalDriveStringsA = GetProcAddress(kernel32.dll, "GetLogicalDriveStringsA");
	kernel32.oGetLogicalDriveStringsW = GetProcAddress(kernel32.dll, "GetLogicalDriveStringsW");
	kernel32.oGetLogicalDrives = GetProcAddress(kernel32.dll, "GetLogicalDrives");
	kernel32.oGetLogicalProcessorInformation = GetProcAddress(kernel32.dll, "GetLogicalProcessorInformation");
	kernel32.oGetLogicalProcessorInformationEx = GetProcAddress(kernel32.dll, "GetLogicalProcessorInformationEx");
	kernel32.oGetLongPathNameA = GetProcAddress(kernel32.dll, "GetLongPathNameA");
	kernel32.oGetLongPathNameTransactedA = GetProcAddress(kernel32.dll, "GetLongPathNameTransactedA");
	kernel32.oGetLongPathNameTransactedW = GetProcAddress(kernel32.dll, "GetLongPathNameTransactedW");
	kernel32.oGetLongPathNameW = GetProcAddress(kernel32.dll, "GetLongPathNameW");
	kernel32.oGetMailslotInfo = GetProcAddress(kernel32.dll, "GetMailslotInfo");
	kernel32.oGetMaximumProcessorCount = GetProcAddress(kernel32.dll, "GetMaximumProcessorCount");
	kernel32.oGetMaximumProcessorGroupCount = GetProcAddress(kernel32.dll, "GetMaximumProcessorGroupCount");
	kernel32.oGetMemoryErrorHandlingCapabilities = GetProcAddress(kernel32.dll, "GetMemoryErrorHandlingCapabilities");
	kernel32.oGetModuleFileNameA = GetProcAddress(kernel32.dll, "GetModuleFileNameA");
	kernel32.oGetModuleFileNameW = GetProcAddress(kernel32.dll, "GetModuleFileNameW");
	kernel32.oGetModuleHandleA = GetProcAddress(kernel32.dll, "GetModuleHandleA");
	kernel32.oGetModuleHandleExA = GetProcAddress(kernel32.dll, "GetModuleHandleExA");
	kernel32.oGetModuleHandleExW = GetProcAddress(kernel32.dll, "GetModuleHandleExW");
	kernel32.oGetModuleHandleW = GetProcAddress(kernel32.dll, "GetModuleHandleW");
	kernel32.oGetNLSVersion = GetProcAddress(kernel32.dll, "GetNLSVersion");
	kernel32.oGetNLSVersionEx = GetProcAddress(kernel32.dll, "GetNLSVersionEx");
	kernel32.oGetNamedPipeAttribute = GetProcAddress(kernel32.dll, "GetNamedPipeAttribute");
	kernel32.oGetNamedPipeClientComputerNameA = GetProcAddress(kernel32.dll, "GetNamedPipeClientComputerNameA");
	kernel32.oGetNamedPipeClientComputerNameW = GetProcAddress(kernel32.dll, "GetNamedPipeClientComputerNameW");
	kernel32.oGetNamedPipeClientProcessId = GetProcAddress(kernel32.dll, "GetNamedPipeClientProcessId");
	kernel32.oGetNamedPipeClientSessionId = GetProcAddress(kernel32.dll, "GetNamedPipeClientSessionId");
	kernel32.oGetNamedPipeHandleStateA = GetProcAddress(kernel32.dll, "GetNamedPipeHandleStateA");
	kernel32.oGetNamedPipeHandleStateW = GetProcAddress(kernel32.dll, "GetNamedPipeHandleStateW");
	kernel32.oGetNamedPipeInfo = GetProcAddress(kernel32.dll, "GetNamedPipeInfo");
	kernel32.oGetNamedPipeServerProcessId = GetProcAddress(kernel32.dll, "GetNamedPipeServerProcessId");
	kernel32.oGetNamedPipeServerSessionId = GetProcAddress(kernel32.dll, "GetNamedPipeServerSessionId");
	kernel32.oGetNativeSystemInfo = GetProcAddress(kernel32.dll, "GetNativeSystemInfo");
	kernel32.oGetNextUmsListItem = GetProcAddress(kernel32.dll, "GetNextUmsListItem");
	kernel32.oGetNextVDMCommand = GetProcAddress(kernel32.dll, "GetNextVDMCommand");
	kernel32.oGetNumaAvailableMemoryNode = GetProcAddress(kernel32.dll, "GetNumaAvailableMemoryNode");
	kernel32.oGetNumaAvailableMemoryNodeEx = GetProcAddress(kernel32.dll, "GetNumaAvailableMemoryNodeEx");
	kernel32.oGetNumaHighestNodeNumber = GetProcAddress(kernel32.dll, "GetNumaHighestNodeNumber");
	kernel32.oGetNumaNodeNumberFromHandle = GetProcAddress(kernel32.dll, "GetNumaNodeNumberFromHandle");
	kernel32.oGetNumaNodeProcessorMask = GetProcAddress(kernel32.dll, "GetNumaNodeProcessorMask");
	kernel32.oGetNumaNodeProcessorMaskEx = GetProcAddress(kernel32.dll, "GetNumaNodeProcessorMaskEx");
	kernel32.oGetNumaProcessorNode = GetProcAddress(kernel32.dll, "GetNumaProcessorNode");
	kernel32.oGetNumaProcessorNodeEx = GetProcAddress(kernel32.dll, "GetNumaProcessorNodeEx");
	kernel32.oGetNumaProximityNode = GetProcAddress(kernel32.dll, "GetNumaProximityNode");
	kernel32.oGetNumaProximityNodeEx = GetProcAddress(kernel32.dll, "GetNumaProximityNodeEx");
	kernel32.oGetNumberFormatA = GetProcAddress(kernel32.dll, "GetNumberFormatA");
	kernel32.oGetNumberFormatEx = GetProcAddress(kernel32.dll, "GetNumberFormatEx");
	kernel32.oGetNumberFormatW = GetProcAddress(kernel32.dll, "GetNumberFormatW");
	kernel32.oGetNumberOfConsoleFonts = GetProcAddress(kernel32.dll, "GetNumberOfConsoleFonts");
	kernel32.oGetNumberOfConsoleInputEvents = GetProcAddress(kernel32.dll, "GetNumberOfConsoleInputEvents");
	kernel32.oGetNumberOfConsoleMouseButtons = GetProcAddress(kernel32.dll, "GetNumberOfConsoleMouseButtons");
	kernel32.oGetOEMCP = GetProcAddress(kernel32.dll, "GetOEMCP");
	kernel32.oGetOverlappedResult = GetProcAddress(kernel32.dll, "GetOverlappedResult");
	kernel32.oGetOverlappedResultEx = GetProcAddress(kernel32.dll, "GetOverlappedResultEx");
	kernel32.oGetPackageApplicationIds = GetProcAddress(kernel32.dll, "GetPackageApplicationIds");
	kernel32.oGetPackageFamilyName = GetProcAddress(kernel32.dll, "GetPackageFamilyName");
	kernel32.oGetPackageFullName = GetProcAddress(kernel32.dll, "GetPackageFullName");
	kernel32.oGetPackageId = GetProcAddress(kernel32.dll, "GetPackageId");
	kernel32.oGetPackageInfo = GetProcAddress(kernel32.dll, "GetPackageInfo");
	kernel32.oGetPackagePath = GetProcAddress(kernel32.dll, "GetPackagePath");
	kernel32.oGetPackagePathByFullName = GetProcAddress(kernel32.dll, "GetPackagePathByFullName");
	kernel32.oGetPackagesByPackageFamily = GetProcAddress(kernel32.dll, "GetPackagesByPackageFamily");
	kernel32.oGetPhysicallyInstalledSystemMemory = GetProcAddress(kernel32.dll, "GetPhysicallyInstalledSystemMemory");
	kernel32.oGetPriorityClass = GetProcAddress(kernel32.dll, "GetPriorityClass");
	kernel32.oGetPrivateProfileIntA = GetProcAddress(kernel32.dll, "GetPrivateProfileIntA");
	kernel32.oGetPrivateProfileIntW = GetProcAddress(kernel32.dll, "GetPrivateProfileIntW");
	kernel32.oGetPrivateProfileSectionA = GetProcAddress(kernel32.dll, "GetPrivateProfileSectionA");
	kernel32.oGetPrivateProfileSectionNamesA = GetProcAddress(kernel32.dll, "GetPrivateProfileSectionNamesA");
	kernel32.oGetPrivateProfileSectionNamesW = GetProcAddress(kernel32.dll, "GetPrivateProfileSectionNamesW");
	kernel32.oGetPrivateProfileSectionW = GetProcAddress(kernel32.dll, "GetPrivateProfileSectionW");
	kernel32.oGetPrivateProfileStringA = GetProcAddress(kernel32.dll, "GetPrivateProfileStringA");
	kernel32.oGetPrivateProfileStringW = GetProcAddress(kernel32.dll, "GetPrivateProfileStringW");
	kernel32.oGetPrivateProfileStructA = GetProcAddress(kernel32.dll, "GetPrivateProfileStructA");
	kernel32.oGetPrivateProfileStructW = GetProcAddress(kernel32.dll, "GetPrivateProfileStructW");
	kernel32.oGetProcAddress = GetProcAddress(kernel32.dll, "GetProcAddress");
	kernel32.oGetProcessAffinityMask = GetProcAddress(kernel32.dll, "GetProcessAffinityMask");
	kernel32.oGetProcessDEPPolicy = GetProcAddress(kernel32.dll, "GetProcessDEPPolicy");
	kernel32.oGetProcessDefaultCpuSets = GetProcAddress(kernel32.dll, "GetProcessDefaultCpuSets");
	kernel32.oGetProcessGroupAffinity = GetProcAddress(kernel32.dll, "GetProcessGroupAffinity");
	kernel32.oGetProcessHandleCount = GetProcAddress(kernel32.dll, "GetProcessHandleCount");
	kernel32.oGetProcessHeap = GetProcAddress(kernel32.dll, "GetProcessHeap");
	kernel32.oGetProcessHeaps = GetProcAddress(kernel32.dll, "GetProcessHeaps");
	kernel32.oGetProcessId = GetProcAddress(kernel32.dll, "GetProcessId");
	kernel32.oGetProcessIdOfThread = GetProcAddress(kernel32.dll, "GetProcessIdOfThread");
	kernel32.oGetProcessInformation = GetProcAddress(kernel32.dll, "GetProcessInformation");
	kernel32.oGetProcessIoCounters = GetProcAddress(kernel32.dll, "GetProcessIoCounters");
	kernel32.oGetProcessMitigationPolicy = GetProcAddress(kernel32.dll, "GetProcessMitigationPolicy");
	kernel32.oGetProcessPreferredUILanguages = GetProcAddress(kernel32.dll, "GetProcessPreferredUILanguages");
	kernel32.oGetProcessPriorityBoost = GetProcAddress(kernel32.dll, "GetProcessPriorityBoost");
	kernel32.oGetProcessShutdownParameters = GetProcAddress(kernel32.dll, "GetProcessShutdownParameters");
	kernel32.oGetProcessTimes = GetProcAddress(kernel32.dll, "GetProcessTimes");
	kernel32.oGetProcessVersion = GetProcAddress(kernel32.dll, "GetProcessVersion");
	kernel32.oGetProcessWorkingSetSize = GetProcAddress(kernel32.dll, "GetProcessWorkingSetSize");
	kernel32.oGetProcessWorkingSetSizeEx = GetProcAddress(kernel32.dll, "GetProcessWorkingSetSizeEx");
	kernel32.oGetProcessorSystemCycleTime = GetProcAddress(kernel32.dll, "GetProcessorSystemCycleTime");
	kernel32.oGetProductInfo = GetProcAddress(kernel32.dll, "GetProductInfo");
	kernel32.oGetProfileIntA = GetProcAddress(kernel32.dll, "GetProfileIntA");
	kernel32.oGetProfileIntW = GetProcAddress(kernel32.dll, "GetProfileIntW");
	kernel32.oGetProfileSectionA = GetProcAddress(kernel32.dll, "GetProfileSectionA");
	kernel32.oGetProfileSectionW = GetProcAddress(kernel32.dll, "GetProfileSectionW");
	kernel32.oGetProfileStringA = GetProcAddress(kernel32.dll, "GetProfileStringA");
	kernel32.oGetProfileStringW = GetProcAddress(kernel32.dll, "GetProfileStringW");
	kernel32.oGetQueuedCompletionStatus = GetProcAddress(kernel32.dll, "GetQueuedCompletionStatus");
	kernel32.oGetQueuedCompletionStatusEx = GetProcAddress(kernel32.dll, "GetQueuedCompletionStatusEx");
	kernel32.oGetShortPathNameA = GetProcAddress(kernel32.dll, "GetShortPathNameA");
	kernel32.oGetShortPathNameW = GetProcAddress(kernel32.dll, "GetShortPathNameW");
	kernel32.oGetStagedPackagePathByFullName = GetProcAddress(kernel32.dll, "GetStagedPackagePathByFullName");
	kernel32.oGetStartupInfoA = GetProcAddress(kernel32.dll, "GetStartupInfoA");
	kernel32.oGetStartupInfoW = GetProcAddress(kernel32.dll, "GetStartupInfoW");
	kernel32.oGetStateFolder = GetProcAddress(kernel32.dll, "GetStateFolder");
	kernel32.oGetStdHandle = GetProcAddress(kernel32.dll, "GetStdHandle");
	kernel32.oGetStringScripts = GetProcAddress(kernel32.dll, "GetStringScripts");
	kernel32.oGetStringTypeA = GetProcAddress(kernel32.dll, "GetStringTypeA");
	kernel32.oGetStringTypeExA = GetProcAddress(kernel32.dll, "GetStringTypeExA");
	kernel32.oGetStringTypeExW = GetProcAddress(kernel32.dll, "GetStringTypeExW");
	kernel32.oGetStringTypeW = GetProcAddress(kernel32.dll, "GetStringTypeW");
	kernel32.oGetSystemAppDataKey = GetProcAddress(kernel32.dll, "GetSystemAppDataKey");
	kernel32.oGetSystemCpuSetInformation = GetProcAddress(kernel32.dll, "GetSystemCpuSetInformation");
	kernel32.oGetSystemDEPPolicy = GetProcAddress(kernel32.dll, "GetSystemDEPPolicy");
	kernel32.oGetSystemDefaultLCID = GetProcAddress(kernel32.dll, "GetSystemDefaultLCID");
	kernel32.oGetSystemDefaultLangID = GetProcAddress(kernel32.dll, "GetSystemDefaultLangID");
	kernel32.oGetSystemDefaultLocaleName = GetProcAddress(kernel32.dll, "GetSystemDefaultLocaleName");
	kernel32.oGetSystemDefaultUILanguage = GetProcAddress(kernel32.dll, "GetSystemDefaultUILanguage");
	kernel32.oGetSystemDirectoryA = GetProcAddress(kernel32.dll, "GetSystemDirectoryA");
	kernel32.oGetSystemDirectoryW = GetProcAddress(kernel32.dll, "GetSystemDirectoryW");
	kernel32.oGetSystemFileCacheSize = GetProcAddress(kernel32.dll, "GetSystemFileCacheSize");
	kernel32.oGetSystemFirmwareTable = GetProcAddress(kernel32.dll, "GetSystemFirmwareTable");
	kernel32.oGetSystemInfo = GetProcAddress(kernel32.dll, "GetSystemInfo");
	kernel32.oGetSystemPowerStatus = GetProcAddress(kernel32.dll, "GetSystemPowerStatus");
	kernel32.oGetSystemPreferredUILanguages = GetProcAddress(kernel32.dll, "GetSystemPreferredUILanguages");
	kernel32.oGetSystemRegistryQuota = GetProcAddress(kernel32.dll, "GetSystemRegistryQuota");
	kernel32.oGetSystemTime = GetProcAddress(kernel32.dll, "GetSystemTime");
	kernel32.oGetSystemTimeAdjustment = GetProcAddress(kernel32.dll, "GetSystemTimeAdjustment");
	kernel32.oGetSystemTimeAsFileTime = GetProcAddress(kernel32.dll, "GetSystemTimeAsFileTime");
	kernel32.oGetSystemTimePreciseAsFileTime = GetProcAddress(kernel32.dll, "GetSystemTimePreciseAsFileTime");
	kernel32.oGetSystemTimes = GetProcAddress(kernel32.dll, "GetSystemTimes");
	kernel32.oGetSystemWindowsDirectoryA = GetProcAddress(kernel32.dll, "GetSystemWindowsDirectoryA");
	kernel32.oGetSystemWindowsDirectoryW = GetProcAddress(kernel32.dll, "GetSystemWindowsDirectoryW");
	kernel32.oGetSystemWow64DirectoryA = GetProcAddress(kernel32.dll, "GetSystemWow64DirectoryA");
	kernel32.oGetSystemWow64DirectoryW = GetProcAddress(kernel32.dll, "GetSystemWow64DirectoryW");
	kernel32.oGetTapeParameters = GetProcAddress(kernel32.dll, "GetTapeParameters");
	kernel32.oGetTapePosition = GetProcAddress(kernel32.dll, "GetTapePosition");
	kernel32.oGetTapeStatus = GetProcAddress(kernel32.dll, "GetTapeStatus");
	kernel32.oGetTempFileNameA = GetProcAddress(kernel32.dll, "GetTempFileNameA");
	kernel32.oGetTempFileNameW = GetProcAddress(kernel32.dll, "GetTempFileNameW");
	kernel32.oGetTempPathA = GetProcAddress(kernel32.dll, "GetTempPathA");
	kernel32.oGetTempPathW = GetProcAddress(kernel32.dll, "GetTempPathW");
	kernel32.oGetThreadContext = GetProcAddress(kernel32.dll, "GetThreadContext");
	kernel32.oGetThreadDescription = GetProcAddress(kernel32.dll, "GetThreadDescription");
	kernel32.oGetThreadErrorMode = GetProcAddress(kernel32.dll, "GetThreadErrorMode");
	kernel32.oGetThreadGroupAffinity = GetProcAddress(kernel32.dll, "GetThreadGroupAffinity");
	kernel32.oGetThreadIOPendingFlag = GetProcAddress(kernel32.dll, "GetThreadIOPendingFlag");
	kernel32.oGetThreadId = GetProcAddress(kernel32.dll, "GetThreadId");
	kernel32.oGetThreadIdealProcessorEx = GetProcAddress(kernel32.dll, "GetThreadIdealProcessorEx");
	kernel32.oGetThreadInformation = GetProcAddress(kernel32.dll, "GetThreadInformation");
	kernel32.oGetThreadLocale = GetProcAddress(kernel32.dll, "GetThreadLocale");
	kernel32.oGetThreadPreferredUILanguages = GetProcAddress(kernel32.dll, "GetThreadPreferredUILanguages");
	kernel32.oGetThreadPriority = GetProcAddress(kernel32.dll, "GetThreadPriority");
	kernel32.oGetThreadPriorityBoost = GetProcAddress(kernel32.dll, "GetThreadPriorityBoost");
	kernel32.oGetThreadSelectedCpuSets = GetProcAddress(kernel32.dll, "GetThreadSelectedCpuSets");
	kernel32.oGetThreadSelectorEntry = GetProcAddress(kernel32.dll, "GetThreadSelectorEntry");
	kernel32.oGetThreadTimes = GetProcAddress(kernel32.dll, "GetThreadTimes");
	kernel32.oGetThreadUILanguage = GetProcAddress(kernel32.dll, "GetThreadUILanguage");
	kernel32.oGetTickCount = GetProcAddress(kernel32.dll, "GetTickCount");
	kernel32.oGetTickCount64 = GetProcAddress(kernel32.dll, "GetTickCount64");
	kernel32.oGetTimeFormatA = GetProcAddress(kernel32.dll, "GetTimeFormatA");
	kernel32.oGetTimeFormatAWorker = GetProcAddress(kernel32.dll, "GetTimeFormatAWorker");
	kernel32.oGetTimeFormatEx = GetProcAddress(kernel32.dll, "GetTimeFormatEx");
	kernel32.oGetTimeFormatW = GetProcAddress(kernel32.dll, "GetTimeFormatW");
	kernel32.oGetTimeFormatWWorker = GetProcAddress(kernel32.dll, "GetTimeFormatWWorker");
	kernel32.oGetTimeZoneInformation = GetProcAddress(kernel32.dll, "GetTimeZoneInformation");
	kernel32.oGetTimeZoneInformationForYear = GetProcAddress(kernel32.dll, "GetTimeZoneInformationForYear");
	kernel32.oGetUILanguageInfo = GetProcAddress(kernel32.dll, "GetUILanguageInfo");
	kernel32.oGetUmsCompletionListEvent = GetProcAddress(kernel32.dll, "GetUmsCompletionListEvent");
	kernel32.oGetUmsSystemThreadInformation = GetProcAddress(kernel32.dll, "GetUmsSystemThreadInformation");
	kernel32.oGetUserDefaultGeoName = GetProcAddress(kernel32.dll, "GetUserDefaultGeoName");
	kernel32.oGetUserDefaultLCID = GetProcAddress(kernel32.dll, "GetUserDefaultLCID");
	kernel32.oGetUserDefaultLangID = GetProcAddress(kernel32.dll, "GetUserDefaultLangID");
	kernel32.oGetUserDefaultLocaleName = GetProcAddress(kernel32.dll, "GetUserDefaultLocaleName");
	kernel32.oGetUserDefaultUILanguage = GetProcAddress(kernel32.dll, "GetUserDefaultUILanguage");
	kernel32.oGetUserGeoID = GetProcAddress(kernel32.dll, "GetUserGeoID");
	kernel32.oGetUserPreferredUILanguages = GetProcAddress(kernel32.dll, "GetUserPreferredUILanguages");
	kernel32.oGetVDMCurrentDirectories = GetProcAddress(kernel32.dll, "GetVDMCurrentDirectories");
	kernel32.oGetVersion = GetProcAddress(kernel32.dll, "GetVersion");
	kernel32.oGetVersionExA = GetProcAddress(kernel32.dll, "GetVersionExA");
	kernel32.oGetVersionExW = GetProcAddress(kernel32.dll, "GetVersionExW");
	kernel32.oGetVolumeInformationA = GetProcAddress(kernel32.dll, "GetVolumeInformationA");
	kernel32.oGetVolumeInformationByHandleW = GetProcAddress(kernel32.dll, "GetVolumeInformationByHandleW");
	kernel32.oGetVolumeInformationW = GetProcAddress(kernel32.dll, "GetVolumeInformationW");
	kernel32.oGetVolumeNameForVolumeMountPointA = GetProcAddress(kernel32.dll, "GetVolumeNameForVolumeMountPointA");
	kernel32.oGetVolumeNameForVolumeMountPointW = GetProcAddress(kernel32.dll, "GetVolumeNameForVolumeMountPointW");
	kernel32.oGetVolumePathNameA = GetProcAddress(kernel32.dll, "GetVolumePathNameA");
	kernel32.oGetVolumePathNameW = GetProcAddress(kernel32.dll, "GetVolumePathNameW");
	kernel32.oGetVolumePathNamesForVolumeNameA = GetProcAddress(kernel32.dll, "GetVolumePathNamesForVolumeNameA");
	kernel32.oGetVolumePathNamesForVolumeNameW = GetProcAddress(kernel32.dll, "GetVolumePathNamesForVolumeNameW");
	kernel32.oGetWindowsDirectoryA = GetProcAddress(kernel32.dll, "GetWindowsDirectoryA");
	kernel32.oGetWindowsDirectoryW = GetProcAddress(kernel32.dll, "GetWindowsDirectoryW");
	kernel32.oGetWriteWatch = GetProcAddress(kernel32.dll, "GetWriteWatch");
	kernel32.oGetXStateFeaturesMask = GetProcAddress(kernel32.dll, "GetXStateFeaturesMask");
	kernel32.oGlobalAddAtomA = GetProcAddress(kernel32.dll, "GlobalAddAtomA");
	kernel32.oGlobalAddAtomExA = GetProcAddress(kernel32.dll, "GlobalAddAtomExA");
	kernel32.oGlobalAddAtomExW = GetProcAddress(kernel32.dll, "GlobalAddAtomExW");
	kernel32.oGlobalAddAtomW = GetProcAddress(kernel32.dll, "GlobalAddAtomW");
	kernel32.oGlobalAlloc = GetProcAddress(kernel32.dll, "GlobalAlloc");
	kernel32.oGlobalCompact = GetProcAddress(kernel32.dll, "GlobalCompact");
	kernel32.oGlobalDeleteAtom = GetProcAddress(kernel32.dll, "GlobalDeleteAtom");
	kernel32.oGlobalFindAtomA = GetProcAddress(kernel32.dll, "GlobalFindAtomA");
	kernel32.oGlobalFindAtomW = GetProcAddress(kernel32.dll, "GlobalFindAtomW");
	kernel32.oGlobalFix = GetProcAddress(kernel32.dll, "GlobalFix");
	kernel32.oGlobalFlags = GetProcAddress(kernel32.dll, "GlobalFlags");
	kernel32.oGlobalFree = GetProcAddress(kernel32.dll, "GlobalFree");
	kernel32.oGlobalGetAtomNameA = GetProcAddress(kernel32.dll, "GlobalGetAtomNameA");
	kernel32.oGlobalGetAtomNameW = GetProcAddress(kernel32.dll, "GlobalGetAtomNameW");
	kernel32.oGlobalHandle = GetProcAddress(kernel32.dll, "GlobalHandle");
	kernel32.oGlobalLock = GetProcAddress(kernel32.dll, "GlobalLock");
	kernel32.oGlobalMemoryStatus = GetProcAddress(kernel32.dll, "GlobalMemoryStatus");
	kernel32.oGlobalMemoryStatusEx = GetProcAddress(kernel32.dll, "GlobalMemoryStatusEx");
	kernel32.oGlobalReAlloc = GetProcAddress(kernel32.dll, "GlobalReAlloc");
	kernel32.oGlobalSize = GetProcAddress(kernel32.dll, "GlobalSize");
	kernel32.oGlobalUnWire = GetProcAddress(kernel32.dll, "GlobalUnWire");
	kernel32.oGlobalUnfix = GetProcAddress(kernel32.dll, "GlobalUnfix");
	kernel32.oGlobalUnlock = GetProcAddress(kernel32.dll, "GlobalUnlock");
	kernel32.oGlobalWire = GetProcAddress(kernel32.dll, "GlobalWire");
	kernel32.oHeap32First = GetProcAddress(kernel32.dll, "Heap32First");
	kernel32.oHeap32ListFirst = GetProcAddress(kernel32.dll, "Heap32ListFirst");
	kernel32.oHeap32ListNext = GetProcAddress(kernel32.dll, "Heap32ListNext");
	kernel32.oHeap32Next = GetProcAddress(kernel32.dll, "Heap32Next");
	kernel32.oHeapAlloc = GetProcAddress(kernel32.dll, "HeapAlloc");
	kernel32.oHeapCompact = GetProcAddress(kernel32.dll, "HeapCompact");
	kernel32.oHeapCreate = GetProcAddress(kernel32.dll, "HeapCreate");
	kernel32.oHeapDestroy = GetProcAddress(kernel32.dll, "HeapDestroy");
	kernel32.oHeapFree = GetProcAddress(kernel32.dll, "HeapFree");
	kernel32.oHeapLock = GetProcAddress(kernel32.dll, "HeapLock");
	kernel32.oHeapQueryInformation = GetProcAddress(kernel32.dll, "HeapQueryInformation");
	kernel32.oHeapReAlloc = GetProcAddress(kernel32.dll, "HeapReAlloc");
	kernel32.oHeapSetInformation = GetProcAddress(kernel32.dll, "HeapSetInformation");
	kernel32.oHeapSize = GetProcAddress(kernel32.dll, "HeapSize");
	kernel32.oHeapSummary = GetProcAddress(kernel32.dll, "HeapSummary");
	kernel32.oHeapUnlock = GetProcAddress(kernel32.dll, "HeapUnlock");
	kernel32.oHeapValidate = GetProcAddress(kernel32.dll, "HeapValidate");
	kernel32.oHeapWalk = GetProcAddress(kernel32.dll, "HeapWalk");
	kernel32.oIdnToAscii = GetProcAddress(kernel32.dll, "IdnToAscii");
	kernel32.oIdnToNameprepUnicode = GetProcAddress(kernel32.dll, "IdnToNameprepUnicode");
	kernel32.oIdnToUnicode = GetProcAddress(kernel32.dll, "IdnToUnicode");
	kernel32.oInitAtomTable = GetProcAddress(kernel32.dll, "InitAtomTable");
	kernel32.oInitOnceBeginInitialize = GetProcAddress(kernel32.dll, "InitOnceBeginInitialize");
	kernel32.oInitOnceComplete = GetProcAddress(kernel32.dll, "InitOnceComplete");
	kernel32.oInitOnceExecuteOnce = GetProcAddress(kernel32.dll, "InitOnceExecuteOnce");
	kernel32.oInitOnceInitialize = GetProcAddress(kernel32.dll, "InitOnceInitialize");
	kernel32.oInitializeConditionVariable = GetProcAddress(kernel32.dll, "InitializeConditionVariable");
	kernel32.oInitializeContext = GetProcAddress(kernel32.dll, "InitializeContext");
	kernel32.oInitializeContext2 = GetProcAddress(kernel32.dll, "InitializeContext2");
	kernel32.oInitializeCriticalSection = GetProcAddress(kernel32.dll, "InitializeCriticalSection");
	kernel32.oInitializeCriticalSectionAndSpinCount = GetProcAddress(kernel32.dll, "InitializeCriticalSectionAndSpinCount");
	kernel32.oInitializeCriticalSectionEx = GetProcAddress(kernel32.dll, "InitializeCriticalSectionEx");
	kernel32.oInitializeEnclave = GetProcAddress(kernel32.dll, "InitializeEnclave");
	kernel32.oInitializeProcThreadAttributeList = GetProcAddress(kernel32.dll, "InitializeProcThreadAttributeList");
	kernel32.oInitializeSListHead = GetProcAddress(kernel32.dll, "InitializeSListHead");
	kernel32.oInitializeSRWLock = GetProcAddress(kernel32.dll, "InitializeSRWLock");
	kernel32.oInitializeSynchronizationBarrier = GetProcAddress(kernel32.dll, "InitializeSynchronizationBarrier");
	kernel32.oInstallELAMCertificateInfo = GetProcAddress(kernel32.dll, "InstallELAMCertificateInfo");
	kernel32.oInterlockedFlushSList = GetProcAddress(kernel32.dll, "InterlockedFlushSList");
	kernel32.oInterlockedPopEntrySList = GetProcAddress(kernel32.dll, "InterlockedPopEntrySList");
	kernel32.oInterlockedPushEntrySList = GetProcAddress(kernel32.dll, "InterlockedPushEntrySList");
	kernel32.oInterlockedPushListSList = GetProcAddress(kernel32.dll, "InterlockedPushListSList");
	kernel32.oInterlockedPushListSListEx = GetProcAddress(kernel32.dll, "InterlockedPushListSListEx");
	kernel32.oInvalidateConsoleDIBits = GetProcAddress(kernel32.dll, "InvalidateConsoleDIBits");
	kernel32.oIsBadCodePtr = GetProcAddress(kernel32.dll, "IsBadCodePtr");
	kernel32.oIsBadHugeReadPtr = GetProcAddress(kernel32.dll, "IsBadHugeReadPtr");
	kernel32.oIsBadHugeWritePtr = GetProcAddress(kernel32.dll, "IsBadHugeWritePtr");
	kernel32.oIsBadReadPtr = GetProcAddress(kernel32.dll, "IsBadReadPtr");
	kernel32.oIsBadStringPtrA = GetProcAddress(kernel32.dll, "IsBadStringPtrA");
	kernel32.oIsBadStringPtrW = GetProcAddress(kernel32.dll, "IsBadStringPtrW");
	kernel32.oIsBadWritePtr = GetProcAddress(kernel32.dll, "IsBadWritePtr");
	kernel32.oIsCalendarLeapDay = GetProcAddress(kernel32.dll, "IsCalendarLeapDay");
	kernel32.oIsCalendarLeapMonth = GetProcAddress(kernel32.dll, "IsCalendarLeapMonth");
	kernel32.oIsCalendarLeapYear = GetProcAddress(kernel32.dll, "IsCalendarLeapYear");
	kernel32.oIsDBCSLeadByte = GetProcAddress(kernel32.dll, "IsDBCSLeadByte");
	kernel32.oIsDBCSLeadByteEx = GetProcAddress(kernel32.dll, "IsDBCSLeadByteEx");
	kernel32.oIsDebuggerPresent = GetProcAddress(kernel32.dll, "IsDebuggerPresent");
	kernel32.oIsEnclaveTypeSupported = GetProcAddress(kernel32.dll, "IsEnclaveTypeSupported");
	kernel32.oIsNLSDefinedString = GetProcAddress(kernel32.dll, "IsNLSDefinedString");
	kernel32.oIsNativeVhdBoot = GetProcAddress(kernel32.dll, "IsNativeVhdBoot");
	kernel32.oIsNormalizedString = GetProcAddress(kernel32.dll, "IsNormalizedString");
	kernel32.oIsProcessCritical = GetProcAddress(kernel32.dll, "IsProcessCritical");
	kernel32.oIsProcessInJob = GetProcAddress(kernel32.dll, "IsProcessInJob");
	kernel32.oIsProcessorFeaturePresent = GetProcAddress(kernel32.dll, "IsProcessorFeaturePresent");
	kernel32.oIsSystemResumeAutomatic = GetProcAddress(kernel32.dll, "IsSystemResumeAutomatic");
	kernel32.oIsThreadAFiber = GetProcAddress(kernel32.dll, "IsThreadAFiber");
	kernel32.oIsThreadpoolTimerSet = GetProcAddress(kernel32.dll, "IsThreadpoolTimerSet");
	kernel32.oIsValidCalDateTime = GetProcAddress(kernel32.dll, "IsValidCalDateTime");
	kernel32.oIsValidCodePage = GetProcAddress(kernel32.dll, "IsValidCodePage");
	kernel32.oIsValidLanguageGroup = GetProcAddress(kernel32.dll, "IsValidLanguageGroup");
	kernel32.oIsValidLocale = GetProcAddress(kernel32.dll, "IsValidLocale");
	kernel32.oIsValidLocaleName = GetProcAddress(kernel32.dll, "IsValidLocaleName");
	kernel32.oIsValidNLSVersion = GetProcAddress(kernel32.dll, "IsValidNLSVersion");
	kernel32.oIsWow64GuestMachineSupported = GetProcAddress(kernel32.dll, "IsWow64GuestMachineSupported");
	kernel32.oIsWow64Process = GetProcAddress(kernel32.dll, "IsWow64Process");
	kernel32.oIsWow64Process2 = GetProcAddress(kernel32.dll, "IsWow64Process2");
	kernel32.oK32EmptyWorkingSet = GetProcAddress(kernel32.dll, "K32EmptyWorkingSet");
	kernel32.oK32EnumDeviceDrivers = GetProcAddress(kernel32.dll, "K32EnumDeviceDrivers");
	kernel32.oK32EnumPageFilesA = GetProcAddress(kernel32.dll, "K32EnumPageFilesA");
	kernel32.oK32EnumPageFilesW = GetProcAddress(kernel32.dll, "K32EnumPageFilesW");
	kernel32.oK32EnumProcessModules = GetProcAddress(kernel32.dll, "K32EnumProcessModules");
	kernel32.oK32EnumProcessModulesEx = GetProcAddress(kernel32.dll, "K32EnumProcessModulesEx");
	kernel32.oK32EnumProcesses = GetProcAddress(kernel32.dll, "K32EnumProcesses");
	kernel32.oK32GetDeviceDriverBaseNameA = GetProcAddress(kernel32.dll, "K32GetDeviceDriverBaseNameA");
	kernel32.oK32GetDeviceDriverBaseNameW = GetProcAddress(kernel32.dll, "K32GetDeviceDriverBaseNameW");
	kernel32.oK32GetDeviceDriverFileNameA = GetProcAddress(kernel32.dll, "K32GetDeviceDriverFileNameA");
	kernel32.oK32GetDeviceDriverFileNameW = GetProcAddress(kernel32.dll, "K32GetDeviceDriverFileNameW");
	kernel32.oK32GetMappedFileNameA = GetProcAddress(kernel32.dll, "K32GetMappedFileNameA");
	kernel32.oK32GetMappedFileNameW = GetProcAddress(kernel32.dll, "K32GetMappedFileNameW");
	kernel32.oK32GetModuleBaseNameA = GetProcAddress(kernel32.dll, "K32GetModuleBaseNameA");
	kernel32.oK32GetModuleBaseNameW = GetProcAddress(kernel32.dll, "K32GetModuleBaseNameW");
	kernel32.oK32GetModuleFileNameExA = GetProcAddress(kernel32.dll, "K32GetModuleFileNameExA");
	kernel32.oK32GetModuleFileNameExW = GetProcAddress(kernel32.dll, "K32GetModuleFileNameExW");
	kernel32.oK32GetModuleInformation = GetProcAddress(kernel32.dll, "K32GetModuleInformation");
	kernel32.oK32GetPerformanceInfo = GetProcAddress(kernel32.dll, "K32GetPerformanceInfo");
	kernel32.oK32GetProcessImageFileNameA = GetProcAddress(kernel32.dll, "K32GetProcessImageFileNameA");
	kernel32.oK32GetProcessImageFileNameW = GetProcAddress(kernel32.dll, "K32GetProcessImageFileNameW");
	kernel32.oK32GetProcessMemoryInfo = GetProcAddress(kernel32.dll, "K32GetProcessMemoryInfo");
	kernel32.oK32GetWsChanges = GetProcAddress(kernel32.dll, "K32GetWsChanges");
	kernel32.oK32GetWsChangesEx = GetProcAddress(kernel32.dll, "K32GetWsChangesEx");
	kernel32.oK32InitializeProcessForWsWatch = GetProcAddress(kernel32.dll, "K32InitializeProcessForWsWatch");
	kernel32.oK32QueryWorkingSet = GetProcAddress(kernel32.dll, "K32QueryWorkingSet");
	kernel32.oK32QueryWorkingSetEx = GetProcAddress(kernel32.dll, "K32QueryWorkingSetEx");
	kernel32.oLCIDToLocaleName = GetProcAddress(kernel32.dll, "LCIDToLocaleName");
	kernel32.oLCMapStringA = GetProcAddress(kernel32.dll, "LCMapStringA");
	kernel32.oLCMapStringEx = GetProcAddress(kernel32.dll, "LCMapStringEx");
	kernel32.oLCMapStringW = GetProcAddress(kernel32.dll, "LCMapStringW");
	kernel32.oLZClose = GetProcAddress(kernel32.dll, "LZClose");
	kernel32.oLZCloseFile = GetProcAddress(kernel32.dll, "LZCloseFile");
	kernel32.oLZCopy = GetProcAddress(kernel32.dll, "LZCopy");
	kernel32.oLZCreateFileW = GetProcAddress(kernel32.dll, "LZCreateFileW");
	kernel32.oLZDone = GetProcAddress(kernel32.dll, "LZDone");
	kernel32.oLZInit = GetProcAddress(kernel32.dll, "LZInit");
	kernel32.oLZOpenFileA = GetProcAddress(kernel32.dll, "LZOpenFileA");
	kernel32.oLZOpenFileW = GetProcAddress(kernel32.dll, "LZOpenFileW");
	kernel32.oLZRead = GetProcAddress(kernel32.dll, "LZRead");
	kernel32.oLZSeek = GetProcAddress(kernel32.dll, "LZSeek");
	kernel32.oLZStart = GetProcAddress(kernel32.dll, "LZStart");
	kernel32.oLeaveCriticalSection = GetProcAddress(kernel32.dll, "LeaveCriticalSection");
	kernel32.oLeaveCriticalSectionWhenCallbackReturns = GetProcAddress(kernel32.dll, "LeaveCriticalSectionWhenCallbackReturns");
	kernel32.oLoadAppInitDlls = GetProcAddress(kernel32.dll, "LoadAppInitDlls");
	kernel32.oLoadEnclaveData = GetProcAddress(kernel32.dll, "LoadEnclaveData");
	kernel32.oLoadLibraryA = GetProcAddress(kernel32.dll, "LoadLibraryA");
	kernel32.oLoadLibraryExA = GetProcAddress(kernel32.dll, "LoadLibraryExA");
	kernel32.oLoadLibraryExW = GetProcAddress(kernel32.dll, "LoadLibraryExW");
	kernel32.oLoadLibraryW = GetProcAddress(kernel32.dll, "LoadLibraryW");
	kernel32.oLoadModule = GetProcAddress(kernel32.dll, "LoadModule");
	//kernel32.oLoadPackagedLibrary = GetProcAddress(kernel32.dll, "LoadPackagedLibrary");
	kernel32.oLoadResource = GetProcAddress(kernel32.dll, "LoadResource");
	kernel32.oLoadStringBaseExW = GetProcAddress(kernel32.dll, "LoadStringBaseExW");
	kernel32.oLoadStringBaseW = GetProcAddress(kernel32.dll, "LoadStringBaseW");
	kernel32.oLocalAlloc = GetProcAddress(kernel32.dll, "LocalAlloc");
	kernel32.oLocalCompact = GetProcAddress(kernel32.dll, "LocalCompact");
	kernel32.oLocalFileTimeToFileTime = GetProcAddress(kernel32.dll, "LocalFileTimeToFileTime");
	kernel32.oLocalFileTimeToLocalSystemTime = GetProcAddress(kernel32.dll, "LocalFileTimeToLocalSystemTime");
	kernel32.oLocalFlags = GetProcAddress(kernel32.dll, "LocalFlags");
	kernel32.oLocalFree = GetProcAddress(kernel32.dll, "LocalFree");
	kernel32.oLocalHandle = GetProcAddress(kernel32.dll, "LocalHandle");
	kernel32.oLocalLock = GetProcAddress(kernel32.dll, "LocalLock");
	kernel32.oLocalReAlloc = GetProcAddress(kernel32.dll, "LocalReAlloc");
	kernel32.oLocalShrink = GetProcAddress(kernel32.dll, "LocalShrink");
	kernel32.oLocalSize = GetProcAddress(kernel32.dll, "LocalSize");
	kernel32.oLocalSystemTimeToLocalFileTime = GetProcAddress(kernel32.dll, "LocalSystemTimeToLocalFileTime");
	kernel32.oLocalUnlock = GetProcAddress(kernel32.dll, "LocalUnlock");
	kernel32.oLocaleNameToLCID = GetProcAddress(kernel32.dll, "LocaleNameToLCID");
	kernel32.oLocateXStateFeature = GetProcAddress(kernel32.dll, "LocateXStateFeature");
	kernel32.oLockFile = GetProcAddress(kernel32.dll, "LockFile");
	kernel32.oLockFileEx = GetProcAddress(kernel32.dll, "LockFileEx");
	kernel32.oLockResource = GetProcAddress(kernel32.dll, "LockResource");
	kernel32.oMapUserPhysicalPages = GetProcAddress(kernel32.dll, "MapUserPhysicalPages");
	kernel32.oMapUserPhysicalPagesScatter = GetProcAddress(kernel32.dll, "MapUserPhysicalPagesScatter");
	kernel32.oMapViewOfFile = GetProcAddress(kernel32.dll, "MapViewOfFile");
	kernel32.oMapViewOfFileEx = GetProcAddress(kernel32.dll, "MapViewOfFileEx");
	kernel32.oMapViewOfFileExNuma = GetProcAddress(kernel32.dll, "MapViewOfFileExNuma");
	kernel32.oMapViewOfFileFromApp = GetProcAddress(kernel32.dll, "MapViewOfFileFromApp");
	kernel32.oModule32First = GetProcAddress(kernel32.dll, "Module32First");
	kernel32.oModule32FirstW = GetProcAddress(kernel32.dll, "Module32FirstW");
	kernel32.oModule32Next = GetProcAddress(kernel32.dll, "Module32Next");
	kernel32.oModule32NextW = GetProcAddress(kernel32.dll, "Module32NextW");
	kernel32.oMoveFileA = GetProcAddress(kernel32.dll, "MoveFileA");
	kernel32.oMoveFileExA = GetProcAddress(kernel32.dll, "MoveFileExA");
	kernel32.oMoveFileExW = GetProcAddress(kernel32.dll, "MoveFileExW");
	kernel32.oMoveFileTransactedA = GetProcAddress(kernel32.dll, "MoveFileTransactedA");
	kernel32.oMoveFileTransactedW = GetProcAddress(kernel32.dll, "MoveFileTransactedW");
	kernel32.oMoveFileW = GetProcAddress(kernel32.dll, "MoveFileW");
	kernel32.oMoveFileWithProgressA = GetProcAddress(kernel32.dll, "MoveFileWithProgressA");
	kernel32.oMoveFileWithProgressW = GetProcAddress(kernel32.dll, "MoveFileWithProgressW");
	kernel32.oMulDiv = GetProcAddress(kernel32.dll, "MulDiv");
	kernel32.oMultiByteToWideChar = GetProcAddress(kernel32.dll, "MultiByteToWideChar");
	kernel32.oNeedCurrentDirectoryForExePathA = GetProcAddress(kernel32.dll, "NeedCurrentDirectoryForExePathA");
	kernel32.oNeedCurrentDirectoryForExePathW = GetProcAddress(kernel32.dll, "NeedCurrentDirectoryForExePathW");
	kernel32.oNlsCheckPolicy = GetProcAddress(kernel32.dll, "NlsCheckPolicy");
	kernel32.oNlsEventDataDescCreate = GetProcAddress(kernel32.dll, "NlsEventDataDescCreate");
	kernel32.oNlsGetCacheUpdateCount = GetProcAddress(kernel32.dll, "NlsGetCacheUpdateCount");
	kernel32.oNlsUpdateLocale = GetProcAddress(kernel32.dll, "NlsUpdateLocale");
	kernel32.oNlsUpdateSystemLocale = GetProcAddress(kernel32.dll, "NlsUpdateSystemLocale");
	kernel32.oNlsWriteEtwEvent = GetProcAddress(kernel32.dll, "NlsWriteEtwEvent");
	kernel32.oNormalizeString = GetProcAddress(kernel32.dll, "NormalizeString");
	kernel32.oNotifyMountMgr = GetProcAddress(kernel32.dll, "NotifyMountMgr");
	kernel32.oNotifyUILanguageChange = GetProcAddress(kernel32.dll, "NotifyUILanguageChange");
	kernel32.oNtVdm64CreateProcessInternalW = GetProcAddress(kernel32.dll, "NtVdm64CreateProcessInternalW");
	kernel32.oOOBEComplete = GetProcAddress(kernel32.dll, "OOBEComplete");
	kernel32.oOfferVirtualMemory = GetProcAddress(kernel32.dll, "OfferVirtualMemory");
	kernel32.oOpenConsoleW = GetProcAddress(kernel32.dll, "OpenConsoleW");
	kernel32.oOpenConsoleWStub = GetProcAddress(kernel32.dll, "OpenConsoleWStub");
	kernel32.oOpenEventA = GetProcAddress(kernel32.dll, "OpenEventA");
	kernel32.oOpenEventW = GetProcAddress(kernel32.dll, "OpenEventW");
	kernel32.oOpenFile = GetProcAddress(kernel32.dll, "OpenFile");
	kernel32.oOpenFileById = GetProcAddress(kernel32.dll, "OpenFileById");
	kernel32.oOpenFileMappingA = GetProcAddress(kernel32.dll, "OpenFileMappingA");
	kernel32.oOpenFileMappingW = GetProcAddress(kernel32.dll, "OpenFileMappingW");
	kernel32.oOpenJobObjectA = GetProcAddress(kernel32.dll, "OpenJobObjectA");
	kernel32.oOpenJobObjectW = GetProcAddress(kernel32.dll, "OpenJobObjectW");
	kernel32.oOpenMutexA = GetProcAddress(kernel32.dll, "OpenMutexA");
	kernel32.oOpenMutexW = GetProcAddress(kernel32.dll, "OpenMutexW");
	kernel32.oOpenPackageInfoByFullName = GetProcAddress(kernel32.dll, "OpenPackageInfoByFullName");
	kernel32.oOpenPrivateNamespaceA = GetProcAddress(kernel32.dll, "OpenPrivateNamespaceA");
	kernel32.oOpenPrivateNamespaceW = GetProcAddress(kernel32.dll, "OpenPrivateNamespaceW");
	kernel32.oOpenProcess = GetProcAddress(kernel32.dll, "OpenProcess");
	kernel32.oOpenProcessToken = GetProcAddress(kernel32.dll, "OpenProcessToken");
	kernel32.oOpenProfileUserMapping = GetProcAddress(kernel32.dll, "OpenProfileUserMapping");
	kernel32.oOpenSemaphoreA = GetProcAddress(kernel32.dll, "OpenSemaphoreA");
	kernel32.oOpenSemaphoreW = GetProcAddress(kernel32.dll, "OpenSemaphoreW");
	kernel32.oOpenState = GetProcAddress(kernel32.dll, "OpenState");
	kernel32.oOpenStateExplicit = GetProcAddress(kernel32.dll, "OpenStateExplicit");
	kernel32.oOpenThread = GetProcAddress(kernel32.dll, "OpenThread");
	kernel32.oOpenThreadToken = GetProcAddress(kernel32.dll, "OpenThreadToken");
	kernel32.oOpenWaitableTimerA = GetProcAddress(kernel32.dll, "OpenWaitableTimerA");
	kernel32.oOpenWaitableTimerW = GetProcAddress(kernel32.dll, "OpenWaitableTimerW");
	kernel32.oOutputDebugStringA = GetProcAddress(kernel32.dll, "OutputDebugStringA");
	kernel32.oOutputDebugStringW = GetProcAddress(kernel32.dll, "OutputDebugStringW");
	kernel32.oPackageFamilyNameFromFullName = GetProcAddress(kernel32.dll, "PackageFamilyNameFromFullName");
	kernel32.oPackageFamilyNameFromId = GetProcAddress(kernel32.dll, "PackageFamilyNameFromId");
	kernel32.oPackageFullNameFromId = GetProcAddress(kernel32.dll, "PackageFullNameFromId");
	kernel32.oPackageIdFromFullName = GetProcAddress(kernel32.dll, "PackageIdFromFullName");
	kernel32.oPackageNameAndPublisherIdFromFamilyName = GetProcAddress(kernel32.dll, "PackageNameAndPublisherIdFromFamilyName");
	kernel32.oParseApplicationUserModelId = GetProcAddress(kernel32.dll, "ParseApplicationUserModelId");
	kernel32.oPeekConsoleInputA = GetProcAddress(kernel32.dll, "PeekConsoleInputA");
	kernel32.oPeekConsoleInputW = GetProcAddress(kernel32.dll, "PeekConsoleInputW");
	kernel32.oPeekNamedPipe = GetProcAddress(kernel32.dll, "PeekNamedPipe");
	kernel32.oPostQueuedCompletionStatus = GetProcAddress(kernel32.dll, "PostQueuedCompletionStatus");
	kernel32.oPowerClearRequest = GetProcAddress(kernel32.dll, "PowerClearRequest");
	kernel32.oPowerCreateRequest = GetProcAddress(kernel32.dll, "PowerCreateRequest");
	kernel32.oPowerSetRequest = GetProcAddress(kernel32.dll, "PowerSetRequest");
	kernel32.oPrefetchVirtualMemory = GetProcAddress(kernel32.dll, "PrefetchVirtualMemory");
	kernel32.oPrepareTape = GetProcAddress(kernel32.dll, "PrepareTape");
	kernel32.oPrivCopyFileExW = GetProcAddress(kernel32.dll, "PrivCopyFileExW");
	kernel32.oPrivMoveFileIdentityW = GetProcAddress(kernel32.dll, "PrivMoveFileIdentityW");
	kernel32.oProcess32First = GetProcAddress(kernel32.dll, "Process32First");
	kernel32.oProcess32FirstW = GetProcAddress(kernel32.dll, "Process32FirstW");
	kernel32.oProcess32Next = GetProcAddress(kernel32.dll, "Process32Next");
	kernel32.oProcess32NextW = GetProcAddress(kernel32.dll, "Process32NextW");
	kernel32.oProcessIdToSessionId = GetProcAddress(kernel32.dll, "ProcessIdToSessionId");
	kernel32.oPssCaptureSnapshot = GetProcAddress(kernel32.dll, "PssCaptureSnapshot");
	kernel32.oPssDuplicateSnapshot = GetProcAddress(kernel32.dll, "PssDuplicateSnapshot");
	kernel32.oPssFreeSnapshot = GetProcAddress(kernel32.dll, "PssFreeSnapshot");
	kernel32.oPssQuerySnapshot = GetProcAddress(kernel32.dll, "PssQuerySnapshot");
	kernel32.oPssWalkMarkerCreate = GetProcAddress(kernel32.dll, "PssWalkMarkerCreate");
	kernel32.oPssWalkMarkerFree = GetProcAddress(kernel32.dll, "PssWalkMarkerFree");
	kernel32.oPssWalkMarkerGetPosition = GetProcAddress(kernel32.dll, "PssWalkMarkerGetPosition");
	kernel32.oPssWalkMarkerRewind = GetProcAddress(kernel32.dll, "PssWalkMarkerRewind");
	kernel32.oPssWalkMarkerSeek = GetProcAddress(kernel32.dll, "PssWalkMarkerSeek");
	kernel32.oPssWalkMarkerSeekToBeginning = GetProcAddress(kernel32.dll, "PssWalkMarkerSeekToBeginning");
	kernel32.oPssWalkMarkerSetPosition = GetProcAddress(kernel32.dll, "PssWalkMarkerSetPosition");
	kernel32.oPssWalkMarkerTell = GetProcAddress(kernel32.dll, "PssWalkMarkerTell");
	kernel32.oPssWalkSnapshot = GetProcAddress(kernel32.dll, "PssWalkSnapshot");
	kernel32.oPulseEvent = GetProcAddress(kernel32.dll, "PulseEvent");
	kernel32.oPurgeComm = GetProcAddress(kernel32.dll, "PurgeComm");
	kernel32.oQueryActCtxSettingsW = GetProcAddress(kernel32.dll, "QueryActCtxSettingsW");
	kernel32.oQueryActCtxSettingsWWorker = GetProcAddress(kernel32.dll, "QueryActCtxSettingsWWorker");
	kernel32.oQueryActCtxW = GetProcAddress(kernel32.dll, "QueryActCtxW");
	kernel32.oQueryActCtxWWorker = GetProcAddress(kernel32.dll, "QueryActCtxWWorker");
	kernel32.oQueryDepthSList = GetProcAddress(kernel32.dll, "QueryDepthSList");
	kernel32.oQueryDosDeviceA = GetProcAddress(kernel32.dll, "QueryDosDeviceA");
	kernel32.oQueryDosDeviceW = GetProcAddress(kernel32.dll, "QueryDosDeviceW");
	kernel32.oQueryFullProcessImageNameA = GetProcAddress(kernel32.dll, "QueryFullProcessImageNameA");
	kernel32.oQueryFullProcessImageNameW = GetProcAddress(kernel32.dll, "QueryFullProcessImageNameW");
	kernel32.oQueryIdleProcessorCycleTime = GetProcAddress(kernel32.dll, "QueryIdleProcessorCycleTime");
	kernel32.oQueryIdleProcessorCycleTimeEx = GetProcAddress(kernel32.dll, "QueryIdleProcessorCycleTimeEx");
	kernel32.oQueryInformationJobObject = GetProcAddress(kernel32.dll, "QueryInformationJobObject");
	kernel32.oQueryIoRateControlInformationJobObject = GetProcAddress(kernel32.dll, "QueryIoRateControlInformationJobObject");
	kernel32.oQueryMemoryResourceNotification = GetProcAddress(kernel32.dll, "QueryMemoryResourceNotification");
	kernel32.oQueryPerformanceCounter = GetProcAddress(kernel32.dll, "QueryPerformanceCounter");
	kernel32.oQueryPerformanceFrequency = GetProcAddress(kernel32.dll, "QueryPerformanceFrequency");
	kernel32.oQueryProcessAffinityUpdateMode = GetProcAddress(kernel32.dll, "QueryProcessAffinityUpdateMode");
	kernel32.oQueryProcessCycleTime = GetProcAddress(kernel32.dll, "QueryProcessCycleTime");
	kernel32.oQueryProtectedPolicy = GetProcAddress(kernel32.dll, "QueryProtectedPolicy");
	kernel32.oQueryThreadCycleTime = GetProcAddress(kernel32.dll, "QueryThreadCycleTime");
	kernel32.oQueryThreadProfiling = GetProcAddress(kernel32.dll, "QueryThreadProfiling");
	kernel32.oQueryThreadpoolStackInformation = GetProcAddress(kernel32.dll, "QueryThreadpoolStackInformation");
	kernel32.oQueryUmsThreadInformation = GetProcAddress(kernel32.dll, "QueryUmsThreadInformation");
	kernel32.oQueryUnbiasedInterruptTime = GetProcAddress(kernel32.dll, "QueryUnbiasedInterruptTime");
	kernel32.oQueueUserAPC = GetProcAddress(kernel32.dll, "QueueUserAPC");
	kernel32.oQueueUserWorkItem = GetProcAddress(kernel32.dll, "QueueUserWorkItem");
	kernel32.oQuirkGetData2Worker = GetProcAddress(kernel32.dll, "QuirkGetData2Worker");
	kernel32.oQuirkGetDataWorker = GetProcAddress(kernel32.dll, "QuirkGetDataWorker");
	kernel32.oQuirkIsEnabled2Worker = GetProcAddress(kernel32.dll, "QuirkIsEnabled2Worker");
	kernel32.oQuirkIsEnabled3Worker = GetProcAddress(kernel32.dll, "QuirkIsEnabled3Worker");
	kernel32.oQuirkIsEnabledForPackage2Worker = GetProcAddress(kernel32.dll, "QuirkIsEnabledForPackage2Worker");
	kernel32.oQuirkIsEnabledForPackage3Worker = GetProcAddress(kernel32.dll, "QuirkIsEnabledForPackage3Worker");
	kernel32.oQuirkIsEnabledForPackage4Worker = GetProcAddress(kernel32.dll, "QuirkIsEnabledForPackage4Worker");
	kernel32.oQuirkIsEnabledForPackageWorker = GetProcAddress(kernel32.dll, "QuirkIsEnabledForPackageWorker");
	kernel32.oQuirkIsEnabledForProcessWorker = GetProcAddress(kernel32.dll, "QuirkIsEnabledForProcessWorker");
	kernel32.oQuirkIsEnabledWorker = GetProcAddress(kernel32.dll, "QuirkIsEnabledWorker");
	kernel32.oRaiseException = GetProcAddress(kernel32.dll, "RaiseException");
	kernel32.oRaiseFailFastException = GetProcAddress(kernel32.dll, "RaiseFailFastException");
	kernel32.oRaiseInvalid16BitExeError = GetProcAddress(kernel32.dll, "RaiseInvalid16BitExeError");
	kernel32.oReOpenFile = GetProcAddress(kernel32.dll, "ReOpenFile");
	kernel32.oReadConsoleA = GetProcAddress(kernel32.dll, "ReadConsoleA");
	kernel32.oReadConsoleInputA = GetProcAddress(kernel32.dll, "ReadConsoleInputA");
	kernel32.oReadConsoleInputExA = GetProcAddress(kernel32.dll, "ReadConsoleInputExA");
	kernel32.oReadConsoleInputExW = GetProcAddress(kernel32.dll, "ReadConsoleInputExW");
	kernel32.oReadConsoleInputW = GetProcAddress(kernel32.dll, "ReadConsoleInputW");
	kernel32.oReadConsoleOutputA = GetProcAddress(kernel32.dll, "ReadConsoleOutputA");
	kernel32.oReadConsoleOutputAttribute = GetProcAddress(kernel32.dll, "ReadConsoleOutputAttribute");
	kernel32.oReadConsoleOutputCharacterA = GetProcAddress(kernel32.dll, "ReadConsoleOutputCharacterA");
	kernel32.oReadConsoleOutputCharacterW = GetProcAddress(kernel32.dll, "ReadConsoleOutputCharacterW");
	kernel32.oReadConsoleOutputW = GetProcAddress(kernel32.dll, "ReadConsoleOutputW");
	kernel32.oReadConsoleW = GetProcAddress(kernel32.dll, "ReadConsoleW");
	kernel32.oReadDirectoryChangesExW = GetProcAddress(kernel32.dll, "ReadDirectoryChangesExW");
	kernel32.oReadDirectoryChangesW = GetProcAddress(kernel32.dll, "ReadDirectoryChangesW");
	kernel32.oReadFile = GetProcAddress(kernel32.dll, "ReadFile");
	kernel32.oReadFileEx = GetProcAddress(kernel32.dll, "ReadFileEx");
	kernel32.oReadFileScatter = GetProcAddress(kernel32.dll, "ReadFileScatter");
	kernel32.oReadProcessMemory = GetProcAddress(kernel32.dll, "ReadProcessMemory");
	kernel32.oReadThreadProfilingData = GetProcAddress(kernel32.dll, "ReadThreadProfilingData");
	kernel32.oReclaimVirtualMemory = GetProcAddress(kernel32.dll, "ReclaimVirtualMemory");
	kernel32.oRegCloseKey = GetProcAddress(kernel32.dll, "RegCloseKey");
	kernel32.oRegCopyTreeW = GetProcAddress(kernel32.dll, "RegCopyTreeW");
	kernel32.oRegCreateKeyExA = GetProcAddress(kernel32.dll, "RegCreateKeyExA");
	kernel32.oRegCreateKeyExW = GetProcAddress(kernel32.dll, "RegCreateKeyExW");
	kernel32.oRegDeleteKeyExA = GetProcAddress(kernel32.dll, "RegDeleteKeyExA");
	kernel32.oRegDeleteKeyExW = GetProcAddress(kernel32.dll, "RegDeleteKeyExW");
	kernel32.oRegDeleteTreeA = GetProcAddress(kernel32.dll, "RegDeleteTreeA");
	kernel32.oRegDeleteTreeW = GetProcAddress(kernel32.dll, "RegDeleteTreeW");
	kernel32.oRegDeleteValueA = GetProcAddress(kernel32.dll, "RegDeleteValueA");
	kernel32.oRegDeleteValueW = GetProcAddress(kernel32.dll, "RegDeleteValueW");
	kernel32.oRegDisablePredefinedCacheEx = GetProcAddress(kernel32.dll, "RegDisablePredefinedCacheEx");
	kernel32.oRegEnumKeyExA = GetProcAddress(kernel32.dll, "RegEnumKeyExA");
	kernel32.oRegEnumKeyExW = GetProcAddress(kernel32.dll, "RegEnumKeyExW");
	kernel32.oRegEnumValueA = GetProcAddress(kernel32.dll, "RegEnumValueA");
	kernel32.oRegEnumValueW = GetProcAddress(kernel32.dll, "RegEnumValueW");
	kernel32.oRegFlushKey = GetProcAddress(kernel32.dll, "RegFlushKey");
	kernel32.oRegGetKeySecurity = GetProcAddress(kernel32.dll, "RegGetKeySecurity");
	kernel32.oRegGetValueA = GetProcAddress(kernel32.dll, "RegGetValueA");
	kernel32.oRegGetValueW = GetProcAddress(kernel32.dll, "RegGetValueW");
	kernel32.oRegLoadKeyA = GetProcAddress(kernel32.dll, "RegLoadKeyA");
	kernel32.oRegLoadKeyW = GetProcAddress(kernel32.dll, "RegLoadKeyW");
	kernel32.oRegLoadMUIStringA = GetProcAddress(kernel32.dll, "RegLoadMUIStringA");
	kernel32.oRegLoadMUIStringW = GetProcAddress(kernel32.dll, "RegLoadMUIStringW");
	kernel32.oRegNotifyChangeKeyValue = GetProcAddress(kernel32.dll, "RegNotifyChangeKeyValue");
	kernel32.oRegOpenCurrentUser = GetProcAddress(kernel32.dll, "RegOpenCurrentUser");
	kernel32.oRegOpenKeyExA = GetProcAddress(kernel32.dll, "RegOpenKeyExA");
	kernel32.oRegOpenKeyExW = GetProcAddress(kernel32.dll, "RegOpenKeyExW");
	kernel32.oRegOpenUserClassesRoot = GetProcAddress(kernel32.dll, "RegOpenUserClassesRoot");
	kernel32.oRegQueryInfoKeyA = GetProcAddress(kernel32.dll, "RegQueryInfoKeyA");
	kernel32.oRegQueryInfoKeyW = GetProcAddress(kernel32.dll, "RegQueryInfoKeyW");
	kernel32.oRegQueryValueExA = GetProcAddress(kernel32.dll, "RegQueryValueExA");
	kernel32.oRegQueryValueExW = GetProcAddress(kernel32.dll, "RegQueryValueExW");
	kernel32.oRegRestoreKeyA = GetProcAddress(kernel32.dll, "RegRestoreKeyA");
	kernel32.oRegRestoreKeyW = GetProcAddress(kernel32.dll, "RegRestoreKeyW");
	kernel32.oRegSaveKeyExA = GetProcAddress(kernel32.dll, "RegSaveKeyExA");
	kernel32.oRegSaveKeyExW = GetProcAddress(kernel32.dll, "RegSaveKeyExW");
	kernel32.oRegSetKeySecurity = GetProcAddress(kernel32.dll, "RegSetKeySecurity");
	kernel32.oRegSetValueExA = GetProcAddress(kernel32.dll, "RegSetValueExA");
	kernel32.oRegSetValueExW = GetProcAddress(kernel32.dll, "RegSetValueExW");
	kernel32.oRegUnLoadKeyA = GetProcAddress(kernel32.dll, "RegUnLoadKeyA");
	kernel32.oRegUnLoadKeyW = GetProcAddress(kernel32.dll, "RegUnLoadKeyW");
	kernel32.oRegisterApplicationRecoveryCallback = GetProcAddress(kernel32.dll, "RegisterApplicationRecoveryCallback");
	kernel32.oRegisterApplicationRestart = GetProcAddress(kernel32.dll, "RegisterApplicationRestart");
	kernel32.oRegisterBadMemoryNotification = GetProcAddress(kernel32.dll, "RegisterBadMemoryNotification");
	kernel32.oRegisterConsoleIME = GetProcAddress(kernel32.dll, "RegisterConsoleIME");
	kernel32.oRegisterConsoleOS2 = GetProcAddress(kernel32.dll, "RegisterConsoleOS2");
	kernel32.oRegisterConsoleVDM = GetProcAddress(kernel32.dll, "RegisterConsoleVDM");
	kernel32.oRegisterWaitForInputIdle = GetProcAddress(kernel32.dll, "RegisterWaitForInputIdle");
	kernel32.oRegisterWaitForSingleObject = GetProcAddress(kernel32.dll, "RegisterWaitForSingleObject");
	kernel32.oRegisterWaitForSingleObjectEx = GetProcAddress(kernel32.dll, "RegisterWaitForSingleObjectEx");
	kernel32.oRegisterWaitUntilOOBECompleted = GetProcAddress(kernel32.dll, "RegisterWaitUntilOOBECompleted");
	kernel32.oRegisterWowBaseHandlers = GetProcAddress(kernel32.dll, "RegisterWowBaseHandlers");
	kernel32.oRegisterWowExec = GetProcAddress(kernel32.dll, "RegisterWowExec");
	kernel32.oReleaseActCtx = GetProcAddress(kernel32.dll, "ReleaseActCtx");
	kernel32.oReleaseActCtxWorker = GetProcAddress(kernel32.dll, "ReleaseActCtxWorker");
	kernel32.oReleaseMutex = GetProcAddress(kernel32.dll, "ReleaseMutex");
	kernel32.oReleaseMutexWhenCallbackReturns = GetProcAddress(kernel32.dll, "ReleaseMutexWhenCallbackReturns");
	kernel32.oReleaseSRWLockExclusive = GetProcAddress(kernel32.dll, "ReleaseSRWLockExclusive");
	kernel32.oReleaseSRWLockShared = GetProcAddress(kernel32.dll, "ReleaseSRWLockShared");
	kernel32.oReleaseSemaphore = GetProcAddress(kernel32.dll, "ReleaseSemaphore");
	kernel32.oReleaseSemaphoreWhenCallbackReturns = GetProcAddress(kernel32.dll, "ReleaseSemaphoreWhenCallbackReturns");
	kernel32.oRemoveDirectoryA = GetProcAddress(kernel32.dll, "RemoveDirectoryA");
	kernel32.oRemoveDirectoryTransactedA = GetProcAddress(kernel32.dll, "RemoveDirectoryTransactedA");
	kernel32.oRemoveDirectoryTransactedW = GetProcAddress(kernel32.dll, "RemoveDirectoryTransactedW");
	kernel32.oRemoveDirectoryW = GetProcAddress(kernel32.dll, "RemoveDirectoryW");
	kernel32.oRemoveDllDirectory = GetProcAddress(kernel32.dll, "RemoveDllDirectory");
	kernel32.oRemoveLocalAlternateComputerNameA = GetProcAddress(kernel32.dll, "RemoveLocalAlternateComputerNameA");
	kernel32.oRemoveLocalAlternateComputerNameW = GetProcAddress(kernel32.dll, "RemoveLocalAlternateComputerNameW");
	kernel32.oRemoveSecureMemoryCacheCallback = GetProcAddress(kernel32.dll, "RemoveSecureMemoryCacheCallback");
	kernel32.oRemoveVectoredContinueHandler = GetProcAddress(kernel32.dll, "RemoveVectoredContinueHandler");
	kernel32.oRemoveVectoredExceptionHandler = GetProcAddress(kernel32.dll, "RemoveVectoredExceptionHandler");
	kernel32.oReplaceFile = GetProcAddress(kernel32.dll, "ReplaceFile");
	kernel32.oReplaceFileA = GetProcAddress(kernel32.dll, "ReplaceFileA");
	kernel32.oReplaceFileW = GetProcAddress(kernel32.dll, "ReplaceFileW");
	kernel32.oReplacePartitionUnit = GetProcAddress(kernel32.dll, "ReplacePartitionUnit");
	kernel32.oRequestDeviceWakeup = GetProcAddress(kernel32.dll, "RequestDeviceWakeup");
	kernel32.oRequestWakeupLatency = GetProcAddress(kernel32.dll, "RequestWakeupLatency");
	kernel32.oResetEvent = GetProcAddress(kernel32.dll, "ResetEvent");
	kernel32.oResetWriteWatch = GetProcAddress(kernel32.dll, "ResetWriteWatch");
	kernel32.oResizePseudoConsole = GetProcAddress(kernel32.dll, "ResizePseudoConsole");
	kernel32.oResolveDelayLoadedAPI = GetProcAddress(kernel32.dll, "ResolveDelayLoadedAPI");
	kernel32.oResolveDelayLoadsFromDll = GetProcAddress(kernel32.dll, "ResolveDelayLoadsFromDll");
	kernel32.oResolveLocaleName = GetProcAddress(kernel32.dll, "ResolveLocaleName");
	kernel32.oRestoreLastError = GetProcAddress(kernel32.dll, "RestoreLastError");
	kernel32.oResumeThread = GetProcAddress(kernel32.dll, "ResumeThread");
	kernel32.oRtlAddFunctionTable = GetProcAddress(kernel32.dll, "RtlAddFunctionTable");
	kernel32.oRtlCaptureContext = GetProcAddress(kernel32.dll, "RtlCaptureContext");
	kernel32.oRtlCaptureStackBackTrace = GetProcAddress(kernel32.dll, "RtlCaptureStackBackTrace");
	kernel32.oRtlCompareMemory = GetProcAddress(kernel32.dll, "RtlCompareMemory");
	kernel32.oRtlCopyMemory = GetProcAddress(kernel32.dll, "RtlCopyMemory");
	kernel32.oRtlDeleteFunctionTable = GetProcAddress(kernel32.dll, "RtlDeleteFunctionTable");
	kernel32.oRtlFillMemory = GetProcAddress(kernel32.dll, "RtlFillMemory");
	kernel32.oRtlInstallFunctionTableCallback = GetProcAddress(kernel32.dll, "RtlInstallFunctionTableCallback");
	kernel32.oRtlLookupFunctionEntry = GetProcAddress(kernel32.dll, "RtlLookupFunctionEntry");
	kernel32.oRtlMoveMemory = GetProcAddress(kernel32.dll, "RtlMoveMemory");
	kernel32.oRtlPcToFileHeader = GetProcAddress(kernel32.dll, "RtlPcToFileHeader");
	kernel32.oRtlRaiseException = GetProcAddress(kernel32.dll, "RtlRaiseException");
	kernel32.oRtlRestoreContext = GetProcAddress(kernel32.dll, "RtlRestoreContext");
	kernel32.oRtlUnwind = GetProcAddress(kernel32.dll, "RtlUnwind");
	kernel32.oRtlUnwindEx = GetProcAddress(kernel32.dll, "RtlUnwindEx");
	kernel32.oRtlVirtualUnwind = GetProcAddress(kernel32.dll, "RtlVirtualUnwind");
	kernel32.oRtlZeroMemory = GetProcAddress(kernel32.dll, "RtlZeroMemory");
	kernel32.oScrollConsoleScreenBufferA = GetProcAddress(kernel32.dll, "ScrollConsoleScreenBufferA");
	kernel32.oScrollConsoleScreenBufferW = GetProcAddress(kernel32.dll, "ScrollConsoleScreenBufferW");
	kernel32.oSearchPathA = GetProcAddress(kernel32.dll, "SearchPathA");
	kernel32.oSearchPathW = GetProcAddress(kernel32.dll, "SearchPathW");
	kernel32.oSetCachedSigningLevel = GetProcAddress(kernel32.dll, "SetCachedSigningLevel");
	kernel32.oSetCalendarInfoA = GetProcAddress(kernel32.dll, "SetCalendarInfoA");
	kernel32.oSetCalendarInfoW = GetProcAddress(kernel32.dll, "SetCalendarInfoW");
	kernel32.oSetComPlusPackageInstallStatus = GetProcAddress(kernel32.dll, "SetComPlusPackageInstallStatus");
	kernel32.oSetCommBreak = GetProcAddress(kernel32.dll, "SetCommBreak");
	kernel32.oSetCommConfig = GetProcAddress(kernel32.dll, "SetCommConfig");
	kernel32.oSetCommMask = GetProcAddress(kernel32.dll, "SetCommMask");
	kernel32.oSetCommState = GetProcAddress(kernel32.dll, "SetCommState");
	kernel32.oSetCommTimeouts = GetProcAddress(kernel32.dll, "SetCommTimeouts");
	kernel32.oSetComputerNameA = GetProcAddress(kernel32.dll, "SetComputerNameA");
	kernel32.oSetComputerNameEx2W = GetProcAddress(kernel32.dll, "SetComputerNameEx2W");
	kernel32.oSetComputerNameExA = GetProcAddress(kernel32.dll, "SetComputerNameExA");
	kernel32.oSetComputerNameExW = GetProcAddress(kernel32.dll, "SetComputerNameExW");
	kernel32.oSetComputerNameW = GetProcAddress(kernel32.dll, "SetComputerNameW");
	kernel32.oSetConsoleActiveScreenBuffer = GetProcAddress(kernel32.dll, "SetConsoleActiveScreenBuffer");
	kernel32.oSetConsoleCP = GetProcAddress(kernel32.dll, "SetConsoleCP");
	kernel32.oSetConsoleCtrlHandler = GetProcAddress(kernel32.dll, "SetConsoleCtrlHandler");
	kernel32.oSetConsoleCursor = GetProcAddress(kernel32.dll, "SetConsoleCursor");
	kernel32.oSetConsoleCursorInfo = GetProcAddress(kernel32.dll, "SetConsoleCursorInfo");
	kernel32.oSetConsoleCursorMode = GetProcAddress(kernel32.dll, "SetConsoleCursorMode");
	kernel32.oSetConsoleCursorPosition = GetProcAddress(kernel32.dll, "SetConsoleCursorPosition");
	kernel32.oSetConsoleDisplayMode = GetProcAddress(kernel32.dll, "SetConsoleDisplayMode");
	kernel32.oSetConsoleFont = GetProcAddress(kernel32.dll, "SetConsoleFont");
	kernel32.oSetConsoleHardwareState = GetProcAddress(kernel32.dll, "SetConsoleHardwareState");
	kernel32.oSetConsoleHistoryInfo = GetProcAddress(kernel32.dll, "SetConsoleHistoryInfo");
	kernel32.oSetConsoleIcon = GetProcAddress(kernel32.dll, "SetConsoleIcon");
	kernel32.oSetConsoleInputExeNameA = GetProcAddress(kernel32.dll, "SetConsoleInputExeNameA");
	kernel32.oSetConsoleInputExeNameW = GetProcAddress(kernel32.dll, "SetConsoleInputExeNameW");
	kernel32.oSetConsoleKeyShortcuts = GetProcAddress(kernel32.dll, "SetConsoleKeyShortcuts");
	kernel32.oSetConsoleLocalEUDC = GetProcAddress(kernel32.dll, "SetConsoleLocalEUDC");
	kernel32.oSetConsoleMaximumWindowSize = GetProcAddress(kernel32.dll, "SetConsoleMaximumWindowSize");
	kernel32.oSetConsoleMenuClose = GetProcAddress(kernel32.dll, "SetConsoleMenuClose");
	kernel32.oSetConsoleMode = GetProcAddress(kernel32.dll, "SetConsoleMode");
	kernel32.oSetConsoleNlsMode = GetProcAddress(kernel32.dll, "SetConsoleNlsMode");
	kernel32.oSetConsoleNumberOfCommandsA = GetProcAddress(kernel32.dll, "SetConsoleNumberOfCommandsA");
	kernel32.oSetConsoleNumberOfCommandsW = GetProcAddress(kernel32.dll, "SetConsoleNumberOfCommandsW");
	kernel32.oSetConsoleOS2OemFormat = GetProcAddress(kernel32.dll, "SetConsoleOS2OemFormat");
	kernel32.oSetConsoleOutputCP = GetProcAddress(kernel32.dll, "SetConsoleOutputCP");
	kernel32.oSetConsolePalette = GetProcAddress(kernel32.dll, "SetConsolePalette");
	kernel32.oSetConsoleScreenBufferInfoEx = GetProcAddress(kernel32.dll, "SetConsoleScreenBufferInfoEx");
	kernel32.oSetConsoleScreenBufferSize = GetProcAddress(kernel32.dll, "SetConsoleScreenBufferSize");
	kernel32.oSetConsoleTextAttribute = GetProcAddress(kernel32.dll, "SetConsoleTextAttribute");
	kernel32.oSetConsoleTitleA = GetProcAddress(kernel32.dll, "SetConsoleTitleA");
	kernel32.oSetConsoleTitleW = GetProcAddress(kernel32.dll, "SetConsoleTitleW");
	kernel32.oSetConsoleWindowInfo = GetProcAddress(kernel32.dll, "SetConsoleWindowInfo");
	kernel32.oSetCriticalSectionSpinCount = GetProcAddress(kernel32.dll, "SetCriticalSectionSpinCount");
	kernel32.oSetCurrentConsoleFontEx = GetProcAddress(kernel32.dll, "SetCurrentConsoleFontEx");
	kernel32.oSetCurrentDirectoryA = GetProcAddress(kernel32.dll, "SetCurrentDirectoryA");
	kernel32.oSetCurrentDirectoryW = GetProcAddress(kernel32.dll, "SetCurrentDirectoryW");
	kernel32.oSetDefaultCommConfigA = GetProcAddress(kernel32.dll, "SetDefaultCommConfigA");
	kernel32.oSetDefaultCommConfigW = GetProcAddress(kernel32.dll, "SetDefaultCommConfigW");
	kernel32.oSetDefaultDllDirectories = GetProcAddress(kernel32.dll, "SetDefaultDllDirectories");
	kernel32.oSetDllDirectoryA = GetProcAddress(kernel32.dll, "SetDllDirectoryA");
	kernel32.oSetDllDirectoryW = GetProcAddress(kernel32.dll, "SetDllDirectoryW");
	kernel32.oSetDynamicTimeZoneInformation = GetProcAddress(kernel32.dll, "SetDynamicTimeZoneInformation");
	kernel32.oSetEndOfFile = GetProcAddress(kernel32.dll, "SetEndOfFile");
	kernel32.oSetEnvironmentStringsA = GetProcAddress(kernel32.dll, "SetEnvironmentStringsA");
	kernel32.oSetEnvironmentStringsW = GetProcAddress(kernel32.dll, "SetEnvironmentStringsW");
	kernel32.oSetEnvironmentVariableA = GetProcAddress(kernel32.dll, "SetEnvironmentVariableA");
	kernel32.oSetEnvironmentVariableW = GetProcAddress(kernel32.dll, "SetEnvironmentVariableW");
	kernel32.oSetErrorMode = GetProcAddress(kernel32.dll, "SetErrorMode");
	kernel32.oSetEvent = GetProcAddress(kernel32.dll, "SetEvent");
	kernel32.oSetEventWhenCallbackReturns = GetProcAddress(kernel32.dll, "SetEventWhenCallbackReturns");
	kernel32.oSetFileApisToANSI = GetProcAddress(kernel32.dll, "SetFileApisToANSI");
	kernel32.oSetFileApisToOEM = GetProcAddress(kernel32.dll, "SetFileApisToOEM");
	kernel32.oSetFileAttributesA = GetProcAddress(kernel32.dll, "SetFileAttributesA");
	kernel32.oSetFileAttributesTransactedA = GetProcAddress(kernel32.dll, "SetFileAttributesTransactedA");
	kernel32.oSetFileAttributesTransactedW = GetProcAddress(kernel32.dll, "SetFileAttributesTransactedW");
	kernel32.oSetFileAttributesW = GetProcAddress(kernel32.dll, "SetFileAttributesW");
	kernel32.oSetFileBandwidthReservation = GetProcAddress(kernel32.dll, "SetFileBandwidthReservation");
	kernel32.oSetFileCompletionNotificationModes = GetProcAddress(kernel32.dll, "SetFileCompletionNotificationModes");
	kernel32.oSetFileInformationByHandle = GetProcAddress(kernel32.dll, "SetFileInformationByHandle");
	kernel32.oSetFileIoOverlappedRange = GetProcAddress(kernel32.dll, "SetFileIoOverlappedRange");
	kernel32.oSetFilePointer = GetProcAddress(kernel32.dll, "SetFilePointer");
	kernel32.oSetFilePointerEx = GetProcAddress(kernel32.dll, "SetFilePointerEx");
	kernel32.oSetFileShortNameA = GetProcAddress(kernel32.dll, "SetFileShortNameA");
	kernel32.oSetFileShortNameW = GetProcAddress(kernel32.dll, "SetFileShortNameW");
	kernel32.oSetFileTime = GetProcAddress(kernel32.dll, "SetFileTime");
	kernel32.oSetFileValidData = GetProcAddress(kernel32.dll, "SetFileValidData");
	kernel32.oSetFirmwareEnvironmentVariableA = GetProcAddress(kernel32.dll, "SetFirmwareEnvironmentVariableA");
	kernel32.oSetFirmwareEnvironmentVariableExA = GetProcAddress(kernel32.dll, "SetFirmwareEnvironmentVariableExA");
	kernel32.oSetFirmwareEnvironmentVariableExW = GetProcAddress(kernel32.dll, "SetFirmwareEnvironmentVariableExW");
	kernel32.oSetFirmwareEnvironmentVariableW = GetProcAddress(kernel32.dll, "SetFirmwareEnvironmentVariableW");
	kernel32.oSetHandleCount = GetProcAddress(kernel32.dll, "SetHandleCount");
	kernel32.oSetHandleInformation = GetProcAddress(kernel32.dll, "SetHandleInformation");
	kernel32.oSetInformationJobObject = GetProcAddress(kernel32.dll, "SetInformationJobObject");
	kernel32.oSetIoRateControlInformationJobObject = GetProcAddress(kernel32.dll, "SetIoRateControlInformationJobObject");
	kernel32.oSetLastConsoleEventActive = GetProcAddress(kernel32.dll, "SetLastConsoleEventActive");
	kernel32.oSetLastError = GetProcAddress(kernel32.dll, "SetLastError");
	kernel32.oSetLocalPrimaryComputerNameA = GetProcAddress(kernel32.dll, "SetLocalPrimaryComputerNameA");
	kernel32.oSetLocalPrimaryComputerNameW = GetProcAddress(kernel32.dll, "SetLocalPrimaryComputerNameW");
	kernel32.oSetLocalTime = GetProcAddress(kernel32.dll, "SetLocalTime");
	kernel32.oSetLocaleInfoA = GetProcAddress(kernel32.dll, "SetLocaleInfoA");
	kernel32.oSetLocaleInfoW = GetProcAddress(kernel32.dll, "SetLocaleInfoW");
	kernel32.oSetMailslotInfo = GetProcAddress(kernel32.dll, "SetMailslotInfo");
	kernel32.oSetMessageWaitingIndicator = GetProcAddress(kernel32.dll, "SetMessageWaitingIndicator");
	kernel32.oSetNamedPipeAttribute = GetProcAddress(kernel32.dll, "SetNamedPipeAttribute");
	kernel32.oSetNamedPipeHandleState = GetProcAddress(kernel32.dll, "SetNamedPipeHandleState");
	kernel32.oSetPriorityClass = GetProcAddress(kernel32.dll, "SetPriorityClass");
	kernel32.oSetProcessAffinityMask = GetProcAddress(kernel32.dll, "SetProcessAffinityMask");
	kernel32.oSetProcessAffinityUpdateMode = GetProcAddress(kernel32.dll, "SetProcessAffinityUpdateMode");
	kernel32.oSetProcessDEPPolicy = GetProcAddress(kernel32.dll, "SetProcessDEPPolicy");
	kernel32.oSetProcessDefaultCpuSets = GetProcAddress(kernel32.dll, "SetProcessDefaultCpuSets");
	kernel32.oSetProcessInformation = GetProcAddress(kernel32.dll, "SetProcessInformation");
	kernel32.oSetProcessMitigationPolicy = GetProcAddress(kernel32.dll, "SetProcessMitigationPolicy");
	kernel32.oSetProcessPreferredUILanguages = GetProcAddress(kernel32.dll, "SetProcessPreferredUILanguages");
	kernel32.oSetProcessPriorityBoost = GetProcAddress(kernel32.dll, "SetProcessPriorityBoost");
	kernel32.oSetProcessShutdownParameters = GetProcAddress(kernel32.dll, "SetProcessShutdownParameters");
	kernel32.oSetProcessWorkingSetSize = GetProcAddress(kernel32.dll, "SetProcessWorkingSetSize");
	kernel32.oSetProcessWorkingSetSizeEx = GetProcAddress(kernel32.dll, "SetProcessWorkingSetSizeEx");
	kernel32.oSetProtectedPolicy = GetProcAddress(kernel32.dll, "SetProtectedPolicy");
	kernel32.oSetSearchPathMode = GetProcAddress(kernel32.dll, "SetSearchPathMode");
	kernel32.oSetStdHandle = GetProcAddress(kernel32.dll, "SetStdHandle");
	kernel32.oSetStdHandleEx = GetProcAddress(kernel32.dll, "SetStdHandleEx");
	kernel32.oSetSystemFileCacheSize = GetProcAddress(kernel32.dll, "SetSystemFileCacheSize");
	kernel32.oSetSystemPowerState = GetProcAddress(kernel32.dll, "SetSystemPowerState");
	kernel32.oSetSystemTime = GetProcAddress(kernel32.dll, "SetSystemTime");
	kernel32.oSetSystemTimeAdjustment = GetProcAddress(kernel32.dll, "SetSystemTimeAdjustment");
	kernel32.oSetTapeParameters = GetProcAddress(kernel32.dll, "SetTapeParameters");
	kernel32.oSetTapePosition = GetProcAddress(kernel32.dll, "SetTapePosition");
	kernel32.oSetTermsrvAppInstallMode = GetProcAddress(kernel32.dll, "SetTermsrvAppInstallMode");
	kernel32.oSetThreadAffinityMask = GetProcAddress(kernel32.dll, "SetThreadAffinityMask");
	kernel32.oSetThreadContext = GetProcAddress(kernel32.dll, "SetThreadContext");
	kernel32.oSetThreadDescription = GetProcAddress(kernel32.dll, "SetThreadDescription");
	kernel32.oSetThreadErrorMode = GetProcAddress(kernel32.dll, "SetThreadErrorMode");
	kernel32.oSetThreadExecutionState = GetProcAddress(kernel32.dll, "SetThreadExecutionState");
	kernel32.oSetThreadGroupAffinity = GetProcAddress(kernel32.dll, "SetThreadGroupAffinity");
	kernel32.oSetThreadIdealProcessor = GetProcAddress(kernel32.dll, "SetThreadIdealProcessor");
	kernel32.oSetThreadIdealProcessorEx = GetProcAddress(kernel32.dll, "SetThreadIdealProcessorEx");
	kernel32.oSetThreadInformation = GetProcAddress(kernel32.dll, "SetThreadInformation");
	kernel32.oSetThreadLocale = GetProcAddress(kernel32.dll, "SetThreadLocale");
	kernel32.oSetThreadPreferredUILanguages = GetProcAddress(kernel32.dll, "SetThreadPreferredUILanguages");
	kernel32.oSetThreadPriority = GetProcAddress(kernel32.dll, "SetThreadPriority");
	kernel32.oSetThreadPriorityBoost = GetProcAddress(kernel32.dll, "SetThreadPriorityBoost");
	kernel32.oSetThreadSelectedCpuSets = GetProcAddress(kernel32.dll, "SetThreadSelectedCpuSets");
	kernel32.oSetThreadStackGuarantee = GetProcAddress(kernel32.dll, "SetThreadStackGuarantee");
	kernel32.oSetThreadToken = GetProcAddress(kernel32.dll, "SetThreadToken");
	kernel32.oSetThreadUILanguage = GetProcAddress(kernel32.dll, "SetThreadUILanguage");
	kernel32.oSetThreadpoolStackInformation = GetProcAddress(kernel32.dll, "SetThreadpoolStackInformation");
	kernel32.oSetThreadpoolThreadMaximum = GetProcAddress(kernel32.dll, "SetThreadpoolThreadMaximum");
	kernel32.oSetThreadpoolThreadMinimum = GetProcAddress(kernel32.dll, "SetThreadpoolThreadMinimum");
	kernel32.oSetThreadpoolTimer = GetProcAddress(kernel32.dll, "SetThreadpoolTimer");
	kernel32.oSetThreadpoolTimerEx = GetProcAddress(kernel32.dll, "SetThreadpoolTimerEx");
	kernel32.oSetThreadpoolWait = GetProcAddress(kernel32.dll, "SetThreadpoolWait");
	kernel32.oSetThreadpoolWaitEx = GetProcAddress(kernel32.dll, "SetThreadpoolWaitEx");
	kernel32.oSetTimeZoneInformation = GetProcAddress(kernel32.dll, "SetTimeZoneInformation");
	kernel32.oSetTimerQueueTimer = GetProcAddress(kernel32.dll, "SetTimerQueueTimer");
	kernel32.oSetUmsThreadInformation = GetProcAddress(kernel32.dll, "SetUmsThreadInformation");
	kernel32.oSetUnhandledExceptionFilter = GetProcAddress(kernel32.dll, "SetUnhandledExceptionFilter");
	kernel32.oSetUserGeoID = GetProcAddress(kernel32.dll, "SetUserGeoID");
	kernel32.oSetUserGeoName = GetProcAddress(kernel32.dll, "SetUserGeoName");
	kernel32.oSetVDMCurrentDirectories = GetProcAddress(kernel32.dll, "SetVDMCurrentDirectories");
	kernel32.oSetVolumeLabelA = GetProcAddress(kernel32.dll, "SetVolumeLabelA");
	kernel32.oSetVolumeLabelW = GetProcAddress(kernel32.dll, "SetVolumeLabelW");
	kernel32.oSetVolumeMountPointA = GetProcAddress(kernel32.dll, "SetVolumeMountPointA");
	kernel32.oSetVolumeMountPointW = GetProcAddress(kernel32.dll, "SetVolumeMountPointW");
	kernel32.oSetVolumeMountPointWStub = GetProcAddress(kernel32.dll, "SetVolumeMountPointWStub");
	kernel32.oSetWaitableTimer = GetProcAddress(kernel32.dll, "SetWaitableTimer");
	kernel32.oSetWaitableTimerEx = GetProcAddress(kernel32.dll, "SetWaitableTimerEx");
	kernel32.oSetXStateFeaturesMask = GetProcAddress(kernel32.dll, "SetXStateFeaturesMask");
	kernel32.oSetupComm = GetProcAddress(kernel32.dll, "SetupComm");
	kernel32.oShowConsoleCursor = GetProcAddress(kernel32.dll, "ShowConsoleCursor");
	kernel32.oSignalObjectAndWait = GetProcAddress(kernel32.dll, "SignalObjectAndWait");
	kernel32.oSizeofResource = GetProcAddress(kernel32.dll, "SizeofResource");
	kernel32.oSleep = GetProcAddress(kernel32.dll, "Sleep");
	kernel32.oSleepConditionVariableCS = GetProcAddress(kernel32.dll, "SleepConditionVariableCS");
	kernel32.oSleepConditionVariableSRW = GetProcAddress(kernel32.dll, "SleepConditionVariableSRW");
	kernel32.oSleepEx = GetProcAddress(kernel32.dll, "SleepEx");
	kernel32.oSortCloseHandle = GetProcAddress(kernel32.dll, "SortCloseHandle");
	kernel32.oSortGetHandle = GetProcAddress(kernel32.dll, "SortGetHandle");
	kernel32.oStartThreadpoolIo = GetProcAddress(kernel32.dll, "StartThreadpoolIo");
	kernel32.oSubmitThreadpoolWork = GetProcAddress(kernel32.dll, "SubmitThreadpoolWork");
	kernel32.oSuspendThread = GetProcAddress(kernel32.dll, "SuspendThread");
	kernel32.oSwitchToFiber = GetProcAddress(kernel32.dll, "SwitchToFiber");
	kernel32.oSwitchToThread = GetProcAddress(kernel32.dll, "SwitchToThread");
	kernel32.oSystemTimeToFileTime = GetProcAddress(kernel32.dll, "SystemTimeToFileTime");
	kernel32.oSystemTimeToTzSpecificLocalTime = GetProcAddress(kernel32.dll, "SystemTimeToTzSpecificLocalTime");
	kernel32.oSystemTimeToTzSpecificLocalTimeEx = GetProcAddress(kernel32.dll, "SystemTimeToTzSpecificLocalTimeEx");
	kernel32.oTerminateJobObject = GetProcAddress(kernel32.dll, "TerminateJobObject");
	kernel32.oTerminateProcess = GetProcAddress(kernel32.dll, "TerminateProcess");
	kernel32.oTerminateThread = GetProcAddress(kernel32.dll, "TerminateThread");
	kernel32.oTermsrvAppInstallMode = GetProcAddress(kernel32.dll, "TermsrvAppInstallMode");
	kernel32.oTermsrvConvertSysRootToUserDir = GetProcAddress(kernel32.dll, "TermsrvConvertSysRootToUserDir");
	kernel32.oTermsrvCreateRegEntry = GetProcAddress(kernel32.dll, "TermsrvCreateRegEntry");
	kernel32.oTermsrvDeleteKey = GetProcAddress(kernel32.dll, "TermsrvDeleteKey");
	kernel32.oTermsrvDeleteValue = GetProcAddress(kernel32.dll, "TermsrvDeleteValue");
	kernel32.oTermsrvGetPreSetValue = GetProcAddress(kernel32.dll, "TermsrvGetPreSetValue");
	kernel32.oTermsrvGetWindowsDirectoryA = GetProcAddress(kernel32.dll, "TermsrvGetWindowsDirectoryA");
	kernel32.oTermsrvGetWindowsDirectoryW = GetProcAddress(kernel32.dll, "TermsrvGetWindowsDirectoryW");
	kernel32.oTermsrvOpenRegEntry = GetProcAddress(kernel32.dll, "TermsrvOpenRegEntry");
	kernel32.oTermsrvOpenUserClasses = GetProcAddress(kernel32.dll, "TermsrvOpenUserClasses");
	kernel32.oTermsrvRestoreKey = GetProcAddress(kernel32.dll, "TermsrvRestoreKey");
	kernel32.oTermsrvSetKeySecurity = GetProcAddress(kernel32.dll, "TermsrvSetKeySecurity");
	kernel32.oTermsrvSetValueKey = GetProcAddress(kernel32.dll, "TermsrvSetValueKey");
	kernel32.oTermsrvSyncUserIniFileExt = GetProcAddress(kernel32.dll, "TermsrvSyncUserIniFileExt");
	kernel32.oThread32First = GetProcAddress(kernel32.dll, "Thread32First");
	kernel32.oThread32Next = GetProcAddress(kernel32.dll, "Thread32Next");
	kernel32.oTlsAlloc = GetProcAddress(kernel32.dll, "TlsAlloc");
	kernel32.oTlsFree = GetProcAddress(kernel32.dll, "TlsFree");
	kernel32.oTlsGetValue = GetProcAddress(kernel32.dll, "TlsGetValue");
	kernel32.oTlsSetValue = GetProcAddress(kernel32.dll, "TlsSetValue");
	kernel32.oToolhelp32ReadProcessMemory = GetProcAddress(kernel32.dll, "Toolhelp32ReadProcessMemory");
	kernel32.oTransactNamedPipe = GetProcAddress(kernel32.dll, "TransactNamedPipe");
	kernel32.oTransmitCommChar = GetProcAddress(kernel32.dll, "TransmitCommChar");
	kernel32.oTryAcquireSRWLockExclusive = GetProcAddress(kernel32.dll, "TryAcquireSRWLockExclusive");
	kernel32.oTryAcquireSRWLockShared = GetProcAddress(kernel32.dll, "TryAcquireSRWLockShared");
	kernel32.oTryEnterCriticalSection = GetProcAddress(kernel32.dll, "TryEnterCriticalSection");
	kernel32.oTrySubmitThreadpoolCallback = GetProcAddress(kernel32.dll, "TrySubmitThreadpoolCallback");
	kernel32.oTzSpecificLocalTimeToSystemTime = GetProcAddress(kernel32.dll, "TzSpecificLocalTimeToSystemTime");
	kernel32.oTzSpecificLocalTimeToSystemTimeEx = GetProcAddress(kernel32.dll, "TzSpecificLocalTimeToSystemTimeEx");
	kernel32.oUTRegister = GetProcAddress(kernel32.dll, "UTRegister");
	kernel32.oUTUnRegister = GetProcAddress(kernel32.dll, "UTUnRegister");
	kernel32.oUmsThreadYield = GetProcAddress(kernel32.dll, "UmsThreadYield");
	kernel32.oUnhandledExceptionFilter = GetProcAddress(kernel32.dll, "UnhandledExceptionFilter");
	kernel32.oUnlockFile = GetProcAddress(kernel32.dll, "UnlockFile");
	kernel32.oUnlockFileEx = GetProcAddress(kernel32.dll, "UnlockFileEx");
	kernel32.oUnmapViewOfFile = GetProcAddress(kernel32.dll, "UnmapViewOfFile");
	kernel32.oUnmapViewOfFileEx = GetProcAddress(kernel32.dll, "UnmapViewOfFileEx");
	kernel32.oUnregisterApplicationRecoveryCallback = GetProcAddress(kernel32.dll, "UnregisterApplicationRecoveryCallback");
	kernel32.oUnregisterApplicationRestart = GetProcAddress(kernel32.dll, "UnregisterApplicationRestart");
	kernel32.oUnregisterBadMemoryNotification = GetProcAddress(kernel32.dll, "UnregisterBadMemoryNotification");
	kernel32.oUnregisterConsoleIME = GetProcAddress(kernel32.dll, "UnregisterConsoleIME");
	kernel32.oUnregisterWait = GetProcAddress(kernel32.dll, "UnregisterWait");
	kernel32.oUnregisterWaitEx = GetProcAddress(kernel32.dll, "UnregisterWaitEx");
	kernel32.oUnregisterWaitUntilOOBECompleted = GetProcAddress(kernel32.dll, "UnregisterWaitUntilOOBECompleted");
	kernel32.oUpdateCalendarDayOfWeek = GetProcAddress(kernel32.dll, "UpdateCalendarDayOfWeek");
	kernel32.oUpdateProcThreadAttribute = GetProcAddress(kernel32.dll, "UpdateProcThreadAttribute");
	kernel32.oUpdateResourceA = GetProcAddress(kernel32.dll, "UpdateResourceA");
	kernel32.oUpdateResourceW = GetProcAddress(kernel32.dll, "UpdateResourceW");
	kernel32.oVDMConsoleOperation = GetProcAddress(kernel32.dll, "VDMConsoleOperation");
	kernel32.oVDMOperationStarted = GetProcAddress(kernel32.dll, "VDMOperationStarted");
	kernel32.oVerLanguageNameA = GetProcAddress(kernel32.dll, "VerLanguageNameA");
	kernel32.oVerLanguageNameW = GetProcAddress(kernel32.dll, "VerLanguageNameW");
	kernel32.oVerSetConditionMask = GetProcAddress(kernel32.dll, "VerSetConditionMask");
	kernel32.oVerifyConsoleIoHandle = GetProcAddress(kernel32.dll, "VerifyConsoleIoHandle");
	kernel32.oVerifyScripts = GetProcAddress(kernel32.dll, "VerifyScripts");
	kernel32.oVerifyVersionInfoA = GetProcAddress(kernel32.dll, "VerifyVersionInfoA");
	kernel32.oVerifyVersionInfoW = GetProcAddress(kernel32.dll, "VerifyVersionInfoW");
	kernel32.oVirtualAlloc = GetProcAddress(kernel32.dll, "VirtualAlloc");
	kernel32.oVirtualAllocEx = GetProcAddress(kernel32.dll, "VirtualAllocEx");
	kernel32.oVirtualAllocExNuma = GetProcAddress(kernel32.dll, "VirtualAllocExNuma");
	kernel32.oVirtualFree = GetProcAddress(kernel32.dll, "VirtualFree");
	kernel32.oVirtualFreeEx = GetProcAddress(kernel32.dll, "VirtualFreeEx");
	kernel32.oVirtualLock = GetProcAddress(kernel32.dll, "VirtualLock");
	kernel32.oVirtualProtect = GetProcAddress(kernel32.dll, "VirtualProtect");
	kernel32.oVirtualProtectEx = GetProcAddress(kernel32.dll, "VirtualProtectEx");
	kernel32.oVirtualQuery = GetProcAddress(kernel32.dll, "VirtualQuery");
	kernel32.oVirtualQueryEx = GetProcAddress(kernel32.dll, "VirtualQueryEx");
	kernel32.oVirtualUnlock = GetProcAddress(kernel32.dll, "VirtualUnlock");
	kernel32.oWTSGetActiveConsoleSessionId = GetProcAddress(kernel32.dll, "WTSGetActiveConsoleSessionId");
	kernel32.oWaitCommEvent = GetProcAddress(kernel32.dll, "WaitCommEvent");
	kernel32.oWaitForDebugEvent = GetProcAddress(kernel32.dll, "WaitForDebugEvent");
	kernel32.oWaitForDebugEventEx = GetProcAddress(kernel32.dll, "WaitForDebugEventEx");
	kernel32.oWaitForMultipleObjects = GetProcAddress(kernel32.dll, "WaitForMultipleObjects");
	kernel32.oWaitForMultipleObjectsEx = GetProcAddress(kernel32.dll, "WaitForMultipleObjectsEx");
	kernel32.oWaitForSingleObject = GetProcAddress(kernel32.dll, "WaitForSingleObject");
	kernel32.oWaitForSingleObjectEx = GetProcAddress(kernel32.dll, "WaitForSingleObjectEx");
	kernel32.oWaitForThreadpoolIoCallbacks = GetProcAddress(kernel32.dll, "WaitForThreadpoolIoCallbacks");
	kernel32.oWaitForThreadpoolTimerCallbacks = GetProcAddress(kernel32.dll, "WaitForThreadpoolTimerCallbacks");
	kernel32.oWaitForThreadpoolWaitCallbacks = GetProcAddress(kernel32.dll, "WaitForThreadpoolWaitCallbacks");
	kernel32.oWaitForThreadpoolWorkCallbacks = GetProcAddress(kernel32.dll, "WaitForThreadpoolWorkCallbacks");
	kernel32.oWaitNamedPipeA = GetProcAddress(kernel32.dll, "WaitNamedPipeA");
	kernel32.oWaitNamedPipeW = GetProcAddress(kernel32.dll, "WaitNamedPipeW");
	kernel32.oWakeAllConditionVariable = GetProcAddress(kernel32.dll, "WakeAllConditionVariable");
	kernel32.oWakeConditionVariable = GetProcAddress(kernel32.dll, "WakeConditionVariable");
	kernel32.oWerGetFlags = GetProcAddress(kernel32.dll, "WerGetFlags");
	kernel32.oWerGetFlagsWorker = GetProcAddress(kernel32.dll, "WerGetFlagsWorker");
	kernel32.oWerRegisterAdditionalProcess = GetProcAddress(kernel32.dll, "WerRegisterAdditionalProcess");
	kernel32.oWerRegisterAppLocalDump = GetProcAddress(kernel32.dll, "WerRegisterAppLocalDump");
	kernel32.oWerRegisterCustomMetadata = GetProcAddress(kernel32.dll, "WerRegisterCustomMetadata");
	kernel32.oWerRegisterExcludedMemoryBlock = GetProcAddress(kernel32.dll, "WerRegisterExcludedMemoryBlock");
	kernel32.oWerRegisterFile = GetProcAddress(kernel32.dll, "WerRegisterFile");
	kernel32.oWerRegisterFileWorker = GetProcAddress(kernel32.dll, "WerRegisterFileWorker");
	kernel32.oWerRegisterMemoryBlock = GetProcAddress(kernel32.dll, "WerRegisterMemoryBlock");
	kernel32.oWerRegisterMemoryBlockWorker = GetProcAddress(kernel32.dll, "WerRegisterMemoryBlockWorker");
	kernel32.oWerRegisterRuntimeExceptionModule = GetProcAddress(kernel32.dll, "WerRegisterRuntimeExceptionModule");
	kernel32.oWerRegisterRuntimeExceptionModuleWorker = GetProcAddress(kernel32.dll, "WerRegisterRuntimeExceptionModuleWorker");
	kernel32.oWerSetFlags = GetProcAddress(kernel32.dll, "WerSetFlags");
	kernel32.oWerSetFlagsWorker = GetProcAddress(kernel32.dll, "WerSetFlagsWorker");
	kernel32.oWerUnregisterAdditionalProcess = GetProcAddress(kernel32.dll, "WerUnregisterAdditionalProcess");
	kernel32.oWerUnregisterAppLocalDump = GetProcAddress(kernel32.dll, "WerUnregisterAppLocalDump");
	kernel32.oWerUnregisterCustomMetadata = GetProcAddress(kernel32.dll, "WerUnregisterCustomMetadata");
	kernel32.oWerUnregisterExcludedMemoryBlock = GetProcAddress(kernel32.dll, "WerUnregisterExcludedMemoryBlock");
	kernel32.oWerUnregisterFile = GetProcAddress(kernel32.dll, "WerUnregisterFile");
	kernel32.oWerUnregisterFileWorker = GetProcAddress(kernel32.dll, "WerUnregisterFileWorker");
	kernel32.oWerUnregisterMemoryBlock = GetProcAddress(kernel32.dll, "WerUnregisterMemoryBlock");
	kernel32.oWerUnregisterMemoryBlockWorker = GetProcAddress(kernel32.dll, "WerUnregisterMemoryBlockWorker");
	kernel32.oWerUnregisterRuntimeExceptionModule = GetProcAddress(kernel32.dll, "WerUnregisterRuntimeExceptionModule");
	kernel32.oWerUnregisterRuntimeExceptionModuleWorker = GetProcAddress(kernel32.dll, "WerUnregisterRuntimeExceptionModuleWorker");
	kernel32.oWerpGetDebugger = GetProcAddress(kernel32.dll, "WerpGetDebugger");
	kernel32.oWerpInitiateRemoteRecovery = GetProcAddress(kernel32.dll, "WerpInitiateRemoteRecovery");
	kernel32.oWerpLaunchAeDebug = GetProcAddress(kernel32.dll, "WerpLaunchAeDebug");
	kernel32.oWerpNotifyLoadStringResourceWorker = GetProcAddress(kernel32.dll, "WerpNotifyLoadStringResourceWorker");
	kernel32.oWerpNotifyUseStringResourceWorker = GetProcAddress(kernel32.dll, "WerpNotifyUseStringResourceWorker");
	kernel32.oWideCharToMultiByte = GetProcAddress(kernel32.dll, "WideCharToMultiByte");
	kernel32.oWinExec = GetProcAddress(kernel32.dll, "WinExec");
	kernel32.oWow64DisableWow64FsRedirection = GetProcAddress(kernel32.dll, "Wow64DisableWow64FsRedirection");
	kernel32.oWow64EnableWow64FsRedirection = GetProcAddress(kernel32.dll, "Wow64EnableWow64FsRedirection");
	kernel32.oWow64GetThreadContext = GetProcAddress(kernel32.dll, "Wow64GetThreadContext");
	kernel32.oWow64GetThreadSelectorEntry = GetProcAddress(kernel32.dll, "Wow64GetThreadSelectorEntry");
	kernel32.oWow64RevertWow64FsRedirection = GetProcAddress(kernel32.dll, "Wow64RevertWow64FsRedirection");
	kernel32.oWow64SetThreadContext = GetProcAddress(kernel32.dll, "Wow64SetThreadContext");
	kernel32.oWow64SuspendThread = GetProcAddress(kernel32.dll, "Wow64SuspendThread");
	kernel32.oWriteConsoleA = GetProcAddress(kernel32.dll, "WriteConsoleA");
	kernel32.oWriteConsoleInputA = GetProcAddress(kernel32.dll, "WriteConsoleInputA");
	kernel32.oWriteConsoleInputVDMA = GetProcAddress(kernel32.dll, "WriteConsoleInputVDMA");
	kernel32.oWriteConsoleInputVDMW = GetProcAddress(kernel32.dll, "WriteConsoleInputVDMW");
	kernel32.oWriteConsoleInputW = GetProcAddress(kernel32.dll, "WriteConsoleInputW");
	kernel32.oWriteConsoleOutputA = GetProcAddress(kernel32.dll, "WriteConsoleOutputA");
	kernel32.oWriteConsoleOutputAttribute = GetProcAddress(kernel32.dll, "WriteConsoleOutputAttribute");
	kernel32.oWriteConsoleOutputCharacterA = GetProcAddress(kernel32.dll, "WriteConsoleOutputCharacterA");
	kernel32.oWriteConsoleOutputCharacterW = GetProcAddress(kernel32.dll, "WriteConsoleOutputCharacterW");
	kernel32.oWriteConsoleOutputW = GetProcAddress(kernel32.dll, "WriteConsoleOutputW");
	kernel32.oWriteConsoleW = GetProcAddress(kernel32.dll, "WriteConsoleW");
	kernel32.oWriteFile = GetProcAddress(kernel32.dll, "WriteFile");
	kernel32.oWriteFileEx = GetProcAddress(kernel32.dll, "WriteFileEx");
	kernel32.oWriteFileGather = GetProcAddress(kernel32.dll, "WriteFileGather");
	kernel32.oWritePrivateProfileSectionA = GetProcAddress(kernel32.dll, "WritePrivateProfileSectionA");
	kernel32.oWritePrivateProfileSectionW = GetProcAddress(kernel32.dll, "WritePrivateProfileSectionW");
	kernel32.oWritePrivateProfileStringA = GetProcAddress(kernel32.dll, "WritePrivateProfileStringA");
	kernel32.oWritePrivateProfileStringW = GetProcAddress(kernel32.dll, "WritePrivateProfileStringW");
	kernel32.oWritePrivateProfileStructA = GetProcAddress(kernel32.dll, "WritePrivateProfileStructA");
	kernel32.oWritePrivateProfileStructW = GetProcAddress(kernel32.dll, "WritePrivateProfileStructW");
	kernel32.oWriteProcessMemory = GetProcAddress(kernel32.dll, "WriteProcessMemory");
	kernel32.oWriteProfileSectionA = GetProcAddress(kernel32.dll, "WriteProfileSectionA");
	kernel32.oWriteProfileSectionW = GetProcAddress(kernel32.dll, "WriteProfileSectionW");
	kernel32.oWriteProfileStringA = GetProcAddress(kernel32.dll, "WriteProfileStringA");
	kernel32.oWriteProfileStringW = GetProcAddress(kernel32.dll, "WriteProfileStringW");
	kernel32.oWriteTapemark = GetProcAddress(kernel32.dll, "WriteTapemark");
	kernel32.oZombifyActCtx = GetProcAddress(kernel32.dll, "ZombifyActCtx");
	kernel32.oZombifyActCtxWorker = GetProcAddress(kernel32.dll, "ZombifyActCtxWorker");
	kernel32.o__C_specific_handler = GetProcAddress(kernel32.dll, "__C_specific_handler");
	kernel32.o__chkstk = GetProcAddress(kernel32.dll, "__chkstk");
	kernel32.o__misaligned_access = GetProcAddress(kernel32.dll, "__misaligned_access");
	kernel32.o_hread = GetProcAddress(kernel32.dll, "_hread");
	kernel32.o_hwrite = GetProcAddress(kernel32.dll, "_hwrite");
	kernel32.o_lclose = GetProcAddress(kernel32.dll, "_lclose");
	kernel32.o_lcreat = GetProcAddress(kernel32.dll, "_lcreat");
	kernel32.o_llseek = GetProcAddress(kernel32.dll, "_llseek");
	kernel32.o_local_unwind = GetProcAddress(kernel32.dll, "_local_unwind");
	kernel32.o_lopen = GetProcAddress(kernel32.dll, "_lopen");
	kernel32.o_lread = GetProcAddress(kernel32.dll, "_lread");
	kernel32.o_lwrite = GetProcAddress(kernel32.dll, "_lwrite");
	kernel32.olstrcat = GetProcAddress(kernel32.dll, "lstrcat");
	kernel32.olstrcatA = GetProcAddress(kernel32.dll, "lstrcatA");
	kernel32.olstrcatW = GetProcAddress(kernel32.dll, "lstrcatW");
	kernel32.olstrcmp = GetProcAddress(kernel32.dll, "lstrcmp");
	kernel32.olstrcmpA = GetProcAddress(kernel32.dll, "lstrcmpA");
	kernel32.olstrcmpW = GetProcAddress(kernel32.dll, "lstrcmpW");
	kernel32.olstrcmpi = GetProcAddress(kernel32.dll, "lstrcmpi");
	kernel32.olstrcmpiA = GetProcAddress(kernel32.dll, "lstrcmpiA");
	kernel32.olstrcmpiW = GetProcAddress(kernel32.dll, "lstrcmpiW");
	kernel32.olstrcpy = GetProcAddress(kernel32.dll, "lstrcpy");
	kernel32.olstrcpyA = GetProcAddress(kernel32.dll, "lstrcpyA");
	kernel32.olstrcpyW = GetProcAddress(kernel32.dll, "lstrcpyW");
	kernel32.olstrcpyn = GetProcAddress(kernel32.dll, "lstrcpyn");
	kernel32.olstrcpynA = GetProcAddress(kernel32.dll, "lstrcpynA");
	kernel32.olstrcpynW = GetProcAddress(kernel32.dll, "lstrcpynW");
	kernel32.olstrlen = GetProcAddress(kernel32.dll, "lstrlen");
	kernel32.olstrlenA = GetProcAddress(kernel32.dll, "lstrlenA");
	kernel32.olstrlenW = GetProcAddress(kernel32.dll, "lstrlenW");
	kernel32.otimeBeginPeriod = GetProcAddress(kernel32.dll, "timeBeginPeriod");
	kernel32.otimeEndPeriod = GetProcAddress(kernel32.dll, "timeEndPeriod");
	kernel32.otimeGetDevCaps = GetProcAddress(kernel32.dll, "timeGetDevCaps");
	kernel32.otimeGetSystemTime = GetProcAddress(kernel32.dll, "timeGetSystemTime");
	kernel32.otimeGetTime = GetProcAddress(kernel32.dll, "timeGetTime");
	kernel32.ouaw_lstrcmpW = GetProcAddress(kernel32.dll, "uaw_lstrcmpW");
	kernel32.ouaw_lstrcmpiW = GetProcAddress(kernel32.dll, "uaw_lstrcmpiW");
	kernel32.ouaw_lstrlenW = GetProcAddress(kernel32.dll, "uaw_lstrlenW");
	kernel32.ouaw_wcschr = GetProcAddress(kernel32.dll, "uaw_wcschr");
	kernel32.ouaw_wcscpy = GetProcAddress(kernel32.dll, "uaw_wcscpy");
	kernel32.ouaw_wcsicmp = GetProcAddress(kernel32.dll, "uaw_wcsicmp");
	kernel32.ouaw_wcslen = GetProcAddress(kernel32.dll, "uaw_wcslen");
	kernel32.ouaw_wcsrchr = GetProcAddress(kernel32.dll, "uaw_wcsrchr");
}
#pragma endregion

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		char path[MAX_PATH];
		GetWindowsDirectory(path, sizeof(path));

		// Example: "\\System32\\version.dll"
		strcat_s(path, "\\System32\\kernel32.dll");
		kernel32.dll = LoadLibrary(path);
		setupFunctions();
		
		//MessageBox(0, "DllMain", "Kernel33", MB_ICONERROR);

		// Add here your code, I recommend you to create a thread
		break;
	case DLL_PROCESS_DETACH:
		FreeLibrary(kernel32.dll);
		break;
	}
	return 1;
}
