#include <Windows.h>
#include "cfgmgr32.h"

typedef CONFIGRET (*fpmyCM_Register_Notification)(PCM_NOTIFY_FILTER, PVOID, PCM_NOTIFY_CALLBACK, PHCMNOTIFICATION);


#pragma region Proxy
struct cfgmgr32_dll {
	HMODULE dll;
	FARPROC oCMP_GetBlockedDriverInfo;
	FARPROC oCMP_GetServerSideDeviceInstallFlags;
	FARPROC oCMP_Init_Detection;
	FARPROC oCMP_RegisterServiceNotification;
	FARPROC oCMP_Register_Notification;
	FARPROC oCMP_Report_LogOn;
	FARPROC oCMP_WaitNoPendingInstallEvents;
	FARPROC oCMP_WaitServicesAvailable;
	FARPROC oCM_Add_Driver_PackageW;
	FARPROC oCM_Add_Driver_Package_ExW;
	FARPROC oCM_Add_Empty_Log_Conf;
	FARPROC oCM_Add_Empty_Log_Conf_Ex;
	FARPROC oCM_Add_IDA;
	FARPROC oCM_Add_IDW;
	FARPROC oCM_Add_ID_ExA;
	FARPROC oCM_Add_ID_ExW;
	FARPROC oCM_Add_Range;
	FARPROC oCM_Add_Res_Des;
	FARPROC oCM_Add_Res_Des_Ex;
	FARPROC oCM_Apply_PowerScheme;
	FARPROC oCM_Connect_MachineA;
	FARPROC oCM_Connect_MachineW;
	FARPROC oCM_Create_DevNodeA;
	FARPROC oCM_Create_DevNodeW;
	FARPROC oCM_Create_DevNode_ExA;
	FARPROC oCM_Create_DevNode_ExW;
	FARPROC oCM_Create_Range_List;
	FARPROC oCM_Delete_Class_Key;
	FARPROC oCM_Delete_Class_Key_Ex;
	FARPROC oCM_Delete_DevNode_Key;
	FARPROC oCM_Delete_DevNode_Key_Ex;
	FARPROC oCM_Delete_Device_Interface_KeyA;
	FARPROC oCM_Delete_Device_Interface_KeyW;
	FARPROC oCM_Delete_Device_Interface_Key_ExA;
	FARPROC oCM_Delete_Device_Interface_Key_ExW;
	FARPROC oCM_Delete_Driver_PackageW;
	FARPROC oCM_Delete_Driver_Package_ExW;
	FARPROC oCM_Delete_PowerScheme;
	FARPROC oCM_Delete_Range;
	FARPROC oCM_Detect_Resource_Conflict;
	FARPROC oCM_Detect_Resource_Conflict_Ex;
	FARPROC oCM_Disable_DevNode;
	FARPROC oCM_Disable_DevNode_Ex;
	FARPROC oCM_Disconnect_Machine;
	FARPROC oCM_Dup_Range_List;
	FARPROC oCM_Duplicate_PowerScheme;
	FARPROC oCM_Enable_DevNode;
	FARPROC oCM_Enable_DevNode_Ex;
	FARPROC oCM_Enumerate_Classes;
	FARPROC oCM_Enumerate_Classes_Ex;
	FARPROC oCM_Enumerate_EnumeratorsA;
	FARPROC oCM_Enumerate_EnumeratorsW;
	FARPROC oCM_Enumerate_Enumerators_ExA;
	FARPROC oCM_Enumerate_Enumerators_ExW;
	FARPROC oCM_Find_Range;
	FARPROC oCM_First_Range;
	FARPROC oCM_Free_Log_Conf;
	FARPROC oCM_Free_Log_Conf_Ex;
	FARPROC oCM_Free_Log_Conf_Handle;
	FARPROC oCM_Free_Range_List;
	FARPROC oCM_Free_Res_Des;
	FARPROC oCM_Free_Res_Des_Ex;
	FARPROC oCM_Free_Res_Des_Handle;
	FARPROC oCM_Free_Resource_Conflict_Handle;
	FARPROC oCM_Get_Child;
	FARPROC oCM_Get_Child_Ex;
	FARPROC oCM_Get_Class_Key_NameA;
	FARPROC oCM_Get_Class_Key_NameW;
	FARPROC oCM_Get_Class_Key_Name_ExA;
	FARPROC oCM_Get_Class_Key_Name_ExW;
	FARPROC oCM_Get_Class_NameA;
	FARPROC oCM_Get_Class_NameW;
	FARPROC oCM_Get_Class_Name_ExA;
	FARPROC oCM_Get_Class_Name_ExW;
	FARPROC oCM_Get_Class_PropertyW;
	FARPROC oCM_Get_Class_Property_ExW;
	FARPROC oCM_Get_Class_Property_Keys;
	FARPROC oCM_Get_Class_Property_Keys_Ex;
	FARPROC oCM_Get_Class_Registry_PropertyA;
	FARPROC oCM_Get_Class_Registry_PropertyW;
	FARPROC oCM_Get_Depth;
	FARPROC oCM_Get_Depth_Ex;
	FARPROC oCM_Get_DevNode_Custom_PropertyA;
	FARPROC oCM_Get_DevNode_Custom_PropertyW;
	FARPROC oCM_Get_DevNode_Custom_Property_ExA;
	FARPROC oCM_Get_DevNode_Custom_Property_ExW;
	FARPROC oCM_Get_DevNode_PropertyW;
	FARPROC oCM_Get_DevNode_Property_ExW;
	FARPROC oCM_Get_DevNode_Property_Keys;
	FARPROC oCM_Get_DevNode_Property_Keys_Ex;
	FARPROC oCM_Get_DevNode_Registry_PropertyA;
	FARPROC oCM_Get_DevNode_Registry_PropertyW;
	FARPROC oCM_Get_DevNode_Registry_Property_ExA;
	FARPROC oCM_Get_DevNode_Registry_Property_ExW;
	FARPROC oCM_Get_DevNode_Status;
	FARPROC oCM_Get_DevNode_Status_Ex;
	FARPROC oCM_Get_Device_IDA;
	FARPROC oCM_Get_Device_IDW;
	FARPROC oCM_Get_Device_ID_ExA;
	FARPROC oCM_Get_Device_ID_ExW;
	FARPROC oCM_Get_Device_ID_ListA;
	FARPROC oCM_Get_Device_ID_ListW;
	FARPROC oCM_Get_Device_ID_List_ExA;
	FARPROC oCM_Get_Device_ID_List_ExW;
	FARPROC oCM_Get_Device_ID_List_SizeA;
	FARPROC oCM_Get_Device_ID_List_SizeW;
	FARPROC oCM_Get_Device_ID_List_Size_ExA;
	FARPROC oCM_Get_Device_ID_List_Size_ExW;
	FARPROC oCM_Get_Device_ID_Size;
	FARPROC oCM_Get_Device_ID_Size_Ex;
	FARPROC oCM_Get_Device_Interface_AliasA;
	FARPROC oCM_Get_Device_Interface_AliasW;
	FARPROC oCM_Get_Device_Interface_Alias_ExA;
	FARPROC oCM_Get_Device_Interface_Alias_ExW;
	FARPROC oCM_Get_Device_Interface_ListA;
	FARPROC oCM_Get_Device_Interface_ListW;
	FARPROC oCM_Get_Device_Interface_List_ExA;
	FARPROC oCM_Get_Device_Interface_List_ExW;
	FARPROC oCM_Get_Device_Interface_List_SizeA;
	FARPROC oCM_Get_Device_Interface_List_SizeW;
	FARPROC oCM_Get_Device_Interface_List_Size_ExA;
	FARPROC oCM_Get_Device_Interface_List_Size_ExW;
	FARPROC oCM_Get_Device_Interface_PropertyW;
	FARPROC oCM_Get_Device_Interface_Property_ExW;
	FARPROC oCM_Get_Device_Interface_Property_KeysW;
	FARPROC oCM_Get_Device_Interface_Property_Keys_ExW;
	FARPROC oCM_Get_First_Log_Conf;
	FARPROC oCM_Get_First_Log_Conf_Ex;
	FARPROC oCM_Get_Global_State;
	FARPROC oCM_Get_Global_State_Ex;
	FARPROC oCM_Get_HW_Prof_FlagsA;
	FARPROC oCM_Get_HW_Prof_FlagsW;
	FARPROC oCM_Get_HW_Prof_Flags_ExA;
	FARPROC oCM_Get_HW_Prof_Flags_ExW;
	FARPROC oCM_Get_Hardware_Profile_InfoA;
	FARPROC oCM_Get_Hardware_Profile_InfoW;
	FARPROC oCM_Get_Hardware_Profile_Info_ExA;
	FARPROC oCM_Get_Hardware_Profile_Info_ExW;
	FARPROC oCM_Get_Log_Conf_Priority;
	FARPROC oCM_Get_Log_Conf_Priority_Ex;
	FARPROC oCM_Get_Next_Log_Conf;
	FARPROC oCM_Get_Next_Log_Conf_Ex;
	FARPROC oCM_Get_Next_Res_Des;
	FARPROC oCM_Get_Next_Res_Des_Ex;
	FARPROC oCM_Get_Parent;
	FARPROC oCM_Get_Parent_Ex;
	FARPROC oCM_Get_Res_Des_Data;
	FARPROC oCM_Get_Res_Des_Data_Ex;
	FARPROC oCM_Get_Res_Des_Data_Size;
	FARPROC oCM_Get_Res_Des_Data_Size_Ex;
	FARPROC oCM_Get_Resource_Conflict_Count;
	FARPROC oCM_Get_Resource_Conflict_DetailsA;
	FARPROC oCM_Get_Resource_Conflict_DetailsW;
	FARPROC oCM_Get_Sibling;
	FARPROC oCM_Get_Sibling_Ex;
	FARPROC oCM_Get_Version;
	FARPROC oCM_Get_Version_Ex;
	FARPROC oCM_Import_PowerScheme;
	FARPROC oCM_Install_DevNodeW;
	FARPROC oCM_Install_DevNode_ExW;
	FARPROC oCM_Install_DriverW;
	FARPROC oCM_Intersect_Range_List;
	FARPROC oCM_Invert_Range_List;
	FARPROC oCM_Is_Dock_Station_Present;
	FARPROC oCM_Is_Dock_Station_Present_Ex;
	FARPROC oCM_Is_Version_Available;
	FARPROC oCM_Is_Version_Available_Ex;
	FARPROC oCM_Locate_DevNodeA;
	FARPROC oCM_Locate_DevNodeW;
	FARPROC oCM_Locate_DevNode_ExA;
	FARPROC oCM_Locate_DevNode_ExW;
	FARPROC oCM_MapCrToSpErr;
	FARPROC oCM_MapCrToWin32Err;
	FARPROC oCM_Merge_Range_List;
	FARPROC oCM_Modify_Res_Des;
	FARPROC oCM_Modify_Res_Des_Ex;
	FARPROC oCM_Move_DevNode;
	FARPROC oCM_Move_DevNode_Ex;
	FARPROC oCM_Next_Range;
	FARPROC oCM_Open_Class_KeyA;
	FARPROC oCM_Open_Class_KeyW;
	FARPROC oCM_Open_Class_Key_ExA;
	FARPROC oCM_Open_Class_Key_ExW;
	FARPROC oCM_Open_DevNode_Key;
	FARPROC oCM_Open_DevNode_Key_Ex;
	FARPROC oCM_Open_Device_Interface_KeyA;
	FARPROC oCM_Open_Device_Interface_KeyW;
	FARPROC oCM_Open_Device_Interface_Key_ExA;
	FARPROC oCM_Open_Device_Interface_Key_ExW;
	FARPROC oCM_Query_And_Remove_SubTreeA;
	FARPROC oCM_Query_And_Remove_SubTreeW;
	FARPROC oCM_Query_And_Remove_SubTree_ExA;
	FARPROC oCM_Query_And_Remove_SubTree_ExW;
	FARPROC oCM_Query_Arbitrator_Free_Data;
	FARPROC oCM_Query_Arbitrator_Free_Data_Ex;
	FARPROC oCM_Query_Arbitrator_Free_Size;
	FARPROC oCM_Query_Arbitrator_Free_Size_Ex;
	FARPROC oCM_Query_Remove_SubTree;
	FARPROC oCM_Query_Remove_SubTree_Ex;
	FARPROC oCM_Query_Resource_Conflict_List;
	FARPROC oCM_Reenumerate_DevNode;
	FARPROC oCM_Reenumerate_DevNode_Ex;
	FARPROC oCM_Register_Device_Driver;
	FARPROC oCM_Register_Device_Driver_Ex;
	FARPROC oCM_Register_Device_InterfaceA;
	FARPROC oCM_Register_Device_InterfaceW;
	FARPROC oCM_Register_Device_Interface_ExA;
	FARPROC oCM_Register_Device_Interface_ExW;
	//FARPROC oCM_Register_Notification;
	fpmyCM_Register_Notification oCM_Register_Notification;
	FARPROC oCM_Remove_SubTree;
	FARPROC oCM_Remove_SubTree_Ex;
	FARPROC oCM_Request_Device_EjectA;
	FARPROC oCM_Request_Device_EjectW;
	FARPROC oCM_Request_Device_Eject_ExA;
	FARPROC oCM_Request_Device_Eject_ExW;
	FARPROC oCM_Request_Eject_PC;
	FARPROC oCM_Request_Eject_PC_Ex;
	FARPROC oCM_RestoreAll_DefaultPowerSchemes;
	FARPROC oCM_Restore_DefaultPowerScheme;
	FARPROC oCM_Run_Detection;
	FARPROC oCM_Run_Detection_Ex;
	FARPROC oCM_Set_ActiveScheme;
	FARPROC oCM_Set_Class_PropertyW;
	FARPROC oCM_Set_Class_Property_ExW;
	FARPROC oCM_Set_Class_Registry_PropertyA;
	FARPROC oCM_Set_Class_Registry_PropertyW;
	FARPROC oCM_Set_DevNode_Problem;
	FARPROC oCM_Set_DevNode_Problem_Ex;
	FARPROC oCM_Set_DevNode_PropertyW;
	FARPROC oCM_Set_DevNode_Property_ExW;
	FARPROC oCM_Set_DevNode_Registry_PropertyA;
	FARPROC oCM_Set_DevNode_Registry_PropertyW;
	FARPROC oCM_Set_DevNode_Registry_Property_ExA;
	FARPROC oCM_Set_DevNode_Registry_Property_ExW;
	FARPROC oCM_Set_Device_Interface_PropertyW;
	FARPROC oCM_Set_Device_Interface_Property_ExW;
	FARPROC oCM_Set_HW_Prof;
	FARPROC oCM_Set_HW_Prof_Ex;
	FARPROC oCM_Set_HW_Prof_FlagsA;
	FARPROC oCM_Set_HW_Prof_FlagsW;
	FARPROC oCM_Set_HW_Prof_Flags_ExA;
	FARPROC oCM_Set_HW_Prof_Flags_ExW;
	FARPROC oCM_Setup_DevNode;
	FARPROC oCM_Setup_DevNode_Ex;
	FARPROC oCM_Test_Range_Available;
	FARPROC oCM_Uninstall_DevNode;
	FARPROC oCM_Uninstall_DevNode_Ex;
	FARPROC oCM_Uninstall_DriverW;
	FARPROC oCM_Unregister_Device_InterfaceA;
	FARPROC oCM_Unregister_Device_InterfaceW;
	FARPROC oCM_Unregister_Device_Interface_ExA;
	FARPROC oCM_Unregister_Device_Interface_ExW;
	FARPROC oCM_Unregister_Notification;
	FARPROC oCM_Write_UserPowerKey;
	FARPROC oDevCloseObjectQuery;
	FARPROC oDevCreateObjectQuery;
	FARPROC oDevCreateObjectQueryEx;
	FARPROC oDevCreateObjectQueryFromId;
	FARPROC oDevCreateObjectQueryFromIdEx;
	FARPROC oDevCreateObjectQueryFromIds;
	FARPROC oDevCreateObjectQueryFromIdsEx;
	FARPROC oDevFindProperty;
	FARPROC oDevFreeObjectProperties;
	FARPROC oDevFreeObjects;
	FARPROC oDevGetObjectProperties;
	FARPROC oDevGetObjectPropertiesEx;
	FARPROC oDevGetObjects;
	FARPROC oDevGetObjectsEx;
	FARPROC oDevSetObjectProperties;
	FARPROC oSwDeviceClose;
	FARPROC oSwDeviceCreate;
	FARPROC oSwDeviceGetLifetime;
	FARPROC oSwDeviceInterfacePropertySet;
	FARPROC oSwDeviceInterfaceRegister;
	FARPROC oSwDeviceInterfaceSetState;
	FARPROC oSwDevicePropertySet;
	FARPROC oSwDeviceSetLifetime;
	FARPROC oSwMemFree;
} cfgmgr32;

extern "C" {
	FARPROC PA = 0;
	int runASM();

	void fCMP_GetBlockedDriverInfo() { PA = cfgmgr32.oCMP_GetBlockedDriverInfo; runASM(); }
	void fCMP_GetServerSideDeviceInstallFlags() { PA = cfgmgr32.oCMP_GetServerSideDeviceInstallFlags; runASM(); }
	void fCMP_Init_Detection() { PA = cfgmgr32.oCMP_Init_Detection; runASM(); }
	void fCMP_RegisterServiceNotification() { PA = cfgmgr32.oCMP_RegisterServiceNotification; runASM(); }
	void fCMP_Register_Notification() { PA = cfgmgr32.oCMP_Register_Notification; runASM(); }
	void fCMP_Report_LogOn() { PA = cfgmgr32.oCMP_Report_LogOn; runASM(); }
	void fCMP_WaitNoPendingInstallEvents() { PA = cfgmgr32.oCMP_WaitNoPendingInstallEvents; runASM(); }
	void fCMP_WaitServicesAvailable() { PA = cfgmgr32.oCMP_WaitServicesAvailable; runASM(); }
	void fCM_Add_Driver_PackageW() { PA = cfgmgr32.oCM_Add_Driver_PackageW; runASM(); }
	void fCM_Add_Driver_Package_ExW() { PA = cfgmgr32.oCM_Add_Driver_Package_ExW; runASM(); }
	void fCM_Add_Empty_Log_Conf() { PA = cfgmgr32.oCM_Add_Empty_Log_Conf; runASM(); }
	void fCM_Add_Empty_Log_Conf_Ex() { PA = cfgmgr32.oCM_Add_Empty_Log_Conf_Ex; runASM(); }
	void fCM_Add_IDA() { PA = cfgmgr32.oCM_Add_IDA; runASM(); }
	void fCM_Add_IDW() { PA = cfgmgr32.oCM_Add_IDW; runASM(); }
	void fCM_Add_ID_ExA() { PA = cfgmgr32.oCM_Add_ID_ExA; runASM(); }
	void fCM_Add_ID_ExW() { PA = cfgmgr32.oCM_Add_ID_ExW; runASM(); }
	void fCM_Add_Range() { PA = cfgmgr32.oCM_Add_Range; runASM(); }
	void fCM_Add_Res_Des() { PA = cfgmgr32.oCM_Add_Res_Des; runASM(); }
	void fCM_Add_Res_Des_Ex() { PA = cfgmgr32.oCM_Add_Res_Des_Ex; runASM(); }
	void fCM_Apply_PowerScheme() { PA = cfgmgr32.oCM_Apply_PowerScheme; runASM(); }
	void fCM_Connect_MachineA() { PA = cfgmgr32.oCM_Connect_MachineA; runASM(); }
	void fCM_Connect_MachineW() { PA = cfgmgr32.oCM_Connect_MachineW; runASM(); }
	void fCM_Create_DevNodeA() { PA = cfgmgr32.oCM_Create_DevNodeA; runASM(); }
	void fCM_Create_DevNodeW() { PA = cfgmgr32.oCM_Create_DevNodeW; runASM(); }
	void fCM_Create_DevNode_ExA() { PA = cfgmgr32.oCM_Create_DevNode_ExA; runASM(); }
	void fCM_Create_DevNode_ExW() { PA = cfgmgr32.oCM_Create_DevNode_ExW; runASM(); }
	void fCM_Create_Range_List() { PA = cfgmgr32.oCM_Create_Range_List; runASM(); }
	void fCM_Delete_Class_Key() { PA = cfgmgr32.oCM_Delete_Class_Key; runASM(); }
	void fCM_Delete_Class_Key_Ex() { PA = cfgmgr32.oCM_Delete_Class_Key_Ex; runASM(); }
	void fCM_Delete_DevNode_Key() { PA = cfgmgr32.oCM_Delete_DevNode_Key; runASM(); }
	void fCM_Delete_DevNode_Key_Ex() { PA = cfgmgr32.oCM_Delete_DevNode_Key_Ex; runASM(); }
	void fCM_Delete_Device_Interface_KeyA() { PA = cfgmgr32.oCM_Delete_Device_Interface_KeyA; runASM(); }
	void fCM_Delete_Device_Interface_KeyW() { PA = cfgmgr32.oCM_Delete_Device_Interface_KeyW; runASM(); }
	void fCM_Delete_Device_Interface_Key_ExA() { PA = cfgmgr32.oCM_Delete_Device_Interface_Key_ExA; runASM(); }
	void fCM_Delete_Device_Interface_Key_ExW() { PA = cfgmgr32.oCM_Delete_Device_Interface_Key_ExW; runASM(); }
	void fCM_Delete_Driver_PackageW() { PA = cfgmgr32.oCM_Delete_Driver_PackageW; runASM(); }
	void fCM_Delete_Driver_Package_ExW() { PA = cfgmgr32.oCM_Delete_Driver_Package_ExW; runASM(); }
	void fCM_Delete_PowerScheme() { PA = cfgmgr32.oCM_Delete_PowerScheme; runASM(); }
	void fCM_Delete_Range() { PA = cfgmgr32.oCM_Delete_Range; runASM(); }
	void fCM_Detect_Resource_Conflict() { PA = cfgmgr32.oCM_Detect_Resource_Conflict; runASM(); }
	void fCM_Detect_Resource_Conflict_Ex() { PA = cfgmgr32.oCM_Detect_Resource_Conflict_Ex; runASM(); }
	void fCM_Disable_DevNode() { PA = cfgmgr32.oCM_Disable_DevNode; runASM(); }
	void fCM_Disable_DevNode_Ex() { PA = cfgmgr32.oCM_Disable_DevNode_Ex; runASM(); }
	void fCM_Disconnect_Machine() { PA = cfgmgr32.oCM_Disconnect_Machine; runASM(); }
	void fCM_Dup_Range_List() { PA = cfgmgr32.oCM_Dup_Range_List; runASM(); }
	void fCM_Duplicate_PowerScheme() { PA = cfgmgr32.oCM_Duplicate_PowerScheme; runASM(); }
	void fCM_Enable_DevNode() { PA = cfgmgr32.oCM_Enable_DevNode; runASM(); }
	void fCM_Enable_DevNode_Ex() { PA = cfgmgr32.oCM_Enable_DevNode_Ex; runASM(); }
	void fCM_Enumerate_Classes() { PA = cfgmgr32.oCM_Enumerate_Classes; runASM(); }
	void fCM_Enumerate_Classes_Ex() { PA = cfgmgr32.oCM_Enumerate_Classes_Ex; runASM(); }
	void fCM_Enumerate_EnumeratorsA() { PA = cfgmgr32.oCM_Enumerate_EnumeratorsA; runASM(); }
	void fCM_Enumerate_EnumeratorsW() { PA = cfgmgr32.oCM_Enumerate_EnumeratorsW; runASM(); }
	void fCM_Enumerate_Enumerators_ExA() { PA = cfgmgr32.oCM_Enumerate_Enumerators_ExA; runASM(); }
	void fCM_Enumerate_Enumerators_ExW() { PA = cfgmgr32.oCM_Enumerate_Enumerators_ExW; runASM(); }
	void fCM_Find_Range() { PA = cfgmgr32.oCM_Find_Range; runASM(); }
	void fCM_First_Range() { PA = cfgmgr32.oCM_First_Range; runASM(); }
	void fCM_Free_Log_Conf() { PA = cfgmgr32.oCM_Free_Log_Conf; runASM(); }
	void fCM_Free_Log_Conf_Ex() { PA = cfgmgr32.oCM_Free_Log_Conf_Ex; runASM(); }
	void fCM_Free_Log_Conf_Handle() { PA = cfgmgr32.oCM_Free_Log_Conf_Handle; runASM(); }
	void fCM_Free_Range_List() { PA = cfgmgr32.oCM_Free_Range_List; runASM(); }
	void fCM_Free_Res_Des() { PA = cfgmgr32.oCM_Free_Res_Des; runASM(); }
	void fCM_Free_Res_Des_Ex() { PA = cfgmgr32.oCM_Free_Res_Des_Ex; runASM(); }
	void fCM_Free_Res_Des_Handle() { PA = cfgmgr32.oCM_Free_Res_Des_Handle; runASM(); }
	void fCM_Free_Resource_Conflict_Handle() { PA = cfgmgr32.oCM_Free_Resource_Conflict_Handle; runASM(); }
	void fCM_Get_Child() { PA = cfgmgr32.oCM_Get_Child; runASM(); }
	void fCM_Get_Child_Ex() { PA = cfgmgr32.oCM_Get_Child_Ex; runASM(); }
	void fCM_Get_Class_Key_NameA() { PA = cfgmgr32.oCM_Get_Class_Key_NameA; runASM(); }
	void fCM_Get_Class_Key_NameW() { PA = cfgmgr32.oCM_Get_Class_Key_NameW; runASM(); }
	void fCM_Get_Class_Key_Name_ExA() { PA = cfgmgr32.oCM_Get_Class_Key_Name_ExA; runASM(); }
	void fCM_Get_Class_Key_Name_ExW() { PA = cfgmgr32.oCM_Get_Class_Key_Name_ExW; runASM(); }
	void fCM_Get_Class_NameA() { PA = cfgmgr32.oCM_Get_Class_NameA; runASM(); }
	void fCM_Get_Class_NameW() { PA = cfgmgr32.oCM_Get_Class_NameW; runASM(); }
	void fCM_Get_Class_Name_ExA() { PA = cfgmgr32.oCM_Get_Class_Name_ExA; runASM(); }
	void fCM_Get_Class_Name_ExW() { PA = cfgmgr32.oCM_Get_Class_Name_ExW; runASM(); }
	void fCM_Get_Class_PropertyW() { PA = cfgmgr32.oCM_Get_Class_PropertyW; runASM(); }
	void fCM_Get_Class_Property_ExW() { PA = cfgmgr32.oCM_Get_Class_Property_ExW; runASM(); }
	void fCM_Get_Class_Property_Keys() { PA = cfgmgr32.oCM_Get_Class_Property_Keys; runASM(); }
	void fCM_Get_Class_Property_Keys_Ex() { PA = cfgmgr32.oCM_Get_Class_Property_Keys_Ex; runASM(); }
	void fCM_Get_Class_Registry_PropertyA() { PA = cfgmgr32.oCM_Get_Class_Registry_PropertyA; runASM(); }
	void fCM_Get_Class_Registry_PropertyW() { PA = cfgmgr32.oCM_Get_Class_Registry_PropertyW; runASM(); }
	void fCM_Get_Depth() { PA = cfgmgr32.oCM_Get_Depth; runASM(); }
	void fCM_Get_Depth_Ex() { PA = cfgmgr32.oCM_Get_Depth_Ex; runASM(); }
	void fCM_Get_DevNode_Custom_PropertyA() { PA = cfgmgr32.oCM_Get_DevNode_Custom_PropertyA; runASM(); }
	void fCM_Get_DevNode_Custom_PropertyW() { PA = cfgmgr32.oCM_Get_DevNode_Custom_PropertyW; runASM(); }
	void fCM_Get_DevNode_Custom_Property_ExA() { PA = cfgmgr32.oCM_Get_DevNode_Custom_Property_ExA; runASM(); }
	void fCM_Get_DevNode_Custom_Property_ExW() { PA = cfgmgr32.oCM_Get_DevNode_Custom_Property_ExW; runASM(); }
	void fCM_Get_DevNode_PropertyW() { PA = cfgmgr32.oCM_Get_DevNode_PropertyW; runASM(); }
	void fCM_Get_DevNode_Property_ExW() { PA = cfgmgr32.oCM_Get_DevNode_Property_ExW; runASM(); }
	void fCM_Get_DevNode_Property_Keys() { PA = cfgmgr32.oCM_Get_DevNode_Property_Keys; runASM(); }
	void fCM_Get_DevNode_Property_Keys_Ex() { PA = cfgmgr32.oCM_Get_DevNode_Property_Keys_Ex; runASM(); }
	void fCM_Get_DevNode_Registry_PropertyA() { PA = cfgmgr32.oCM_Get_DevNode_Registry_PropertyA; runASM(); }
	void fCM_Get_DevNode_Registry_PropertyW() { PA = cfgmgr32.oCM_Get_DevNode_Registry_PropertyW; runASM(); }
	void fCM_Get_DevNode_Registry_Property_ExA() { PA = cfgmgr32.oCM_Get_DevNode_Registry_Property_ExA; runASM(); }
	void fCM_Get_DevNode_Registry_Property_ExW() { PA = cfgmgr32.oCM_Get_DevNode_Registry_Property_ExW; runASM(); }
	void fCM_Get_DevNode_Status() { PA = cfgmgr32.oCM_Get_DevNode_Status; runASM(); }
	void fCM_Get_DevNode_Status_Ex() { PA = cfgmgr32.oCM_Get_DevNode_Status_Ex; runASM(); }
	void fCM_Get_Device_IDA() { PA = cfgmgr32.oCM_Get_Device_IDA; runASM(); }
	void fCM_Get_Device_IDW() { PA = cfgmgr32.oCM_Get_Device_IDW; runASM(); }
	void fCM_Get_Device_ID_ExA() { PA = cfgmgr32.oCM_Get_Device_ID_ExA; runASM(); }
	void fCM_Get_Device_ID_ExW() { PA = cfgmgr32.oCM_Get_Device_ID_ExW; runASM(); }
	void fCM_Get_Device_ID_ListA() { PA = cfgmgr32.oCM_Get_Device_ID_ListA; runASM(); }
	void fCM_Get_Device_ID_ListW() { PA = cfgmgr32.oCM_Get_Device_ID_ListW; runASM(); }
	void fCM_Get_Device_ID_List_ExA() { PA = cfgmgr32.oCM_Get_Device_ID_List_ExA; runASM(); }
	void fCM_Get_Device_ID_List_ExW() { PA = cfgmgr32.oCM_Get_Device_ID_List_ExW; runASM(); }
	void fCM_Get_Device_ID_List_SizeA() { PA = cfgmgr32.oCM_Get_Device_ID_List_SizeA; runASM(); }
	void fCM_Get_Device_ID_List_SizeW() { PA = cfgmgr32.oCM_Get_Device_ID_List_SizeW; runASM(); }
	void fCM_Get_Device_ID_List_Size_ExA() { PA = cfgmgr32.oCM_Get_Device_ID_List_Size_ExA; runASM(); }
	void fCM_Get_Device_ID_List_Size_ExW() { PA = cfgmgr32.oCM_Get_Device_ID_List_Size_ExW; runASM(); }
	void fCM_Get_Device_ID_Size() { PA = cfgmgr32.oCM_Get_Device_ID_Size; runASM(); }
	void fCM_Get_Device_ID_Size_Ex() { PA = cfgmgr32.oCM_Get_Device_ID_Size_Ex; runASM(); }
	void fCM_Get_Device_Interface_AliasA() { PA = cfgmgr32.oCM_Get_Device_Interface_AliasA; runASM(); }
	void fCM_Get_Device_Interface_AliasW() { PA = cfgmgr32.oCM_Get_Device_Interface_AliasW; runASM(); }
	void fCM_Get_Device_Interface_Alias_ExA() { PA = cfgmgr32.oCM_Get_Device_Interface_Alias_ExA; runASM(); }
	void fCM_Get_Device_Interface_Alias_ExW() { PA = cfgmgr32.oCM_Get_Device_Interface_Alias_ExW; runASM(); }
	void fCM_Get_Device_Interface_ListA() { PA = cfgmgr32.oCM_Get_Device_Interface_ListA; runASM(); }
	void fCM_Get_Device_Interface_ListW() { PA = cfgmgr32.oCM_Get_Device_Interface_ListW; runASM(); }
	void fCM_Get_Device_Interface_List_ExA() { PA = cfgmgr32.oCM_Get_Device_Interface_List_ExA; runASM(); }
	void fCM_Get_Device_Interface_List_ExW() { PA = cfgmgr32.oCM_Get_Device_Interface_List_ExW; runASM(); }
	void fCM_Get_Device_Interface_List_SizeA() { PA = cfgmgr32.oCM_Get_Device_Interface_List_SizeA; runASM(); }
	void fCM_Get_Device_Interface_List_SizeW() { PA = cfgmgr32.oCM_Get_Device_Interface_List_SizeW; runASM(); }
	void fCM_Get_Device_Interface_List_Size_ExA() { PA = cfgmgr32.oCM_Get_Device_Interface_List_Size_ExA; runASM(); }
	void fCM_Get_Device_Interface_List_Size_ExW() { PA = cfgmgr32.oCM_Get_Device_Interface_List_Size_ExW; runASM(); }
	void fCM_Get_Device_Interface_PropertyW() { PA = cfgmgr32.oCM_Get_Device_Interface_PropertyW; runASM(); }
	void fCM_Get_Device_Interface_Property_ExW() { PA = cfgmgr32.oCM_Get_Device_Interface_Property_ExW; runASM(); }
	void fCM_Get_Device_Interface_Property_KeysW() { PA = cfgmgr32.oCM_Get_Device_Interface_Property_KeysW; runASM(); }
	void fCM_Get_Device_Interface_Property_Keys_ExW() { PA = cfgmgr32.oCM_Get_Device_Interface_Property_Keys_ExW; runASM(); }
	void fCM_Get_First_Log_Conf() { PA = cfgmgr32.oCM_Get_First_Log_Conf; runASM(); }
	void fCM_Get_First_Log_Conf_Ex() { PA = cfgmgr32.oCM_Get_First_Log_Conf_Ex; runASM(); }
	void fCM_Get_Global_State() { PA = cfgmgr32.oCM_Get_Global_State; runASM(); }
	void fCM_Get_Global_State_Ex() { PA = cfgmgr32.oCM_Get_Global_State_Ex; runASM(); }
	void fCM_Get_HW_Prof_FlagsA() { PA = cfgmgr32.oCM_Get_HW_Prof_FlagsA; runASM(); }
	void fCM_Get_HW_Prof_FlagsW() { PA = cfgmgr32.oCM_Get_HW_Prof_FlagsW; runASM(); }
	void fCM_Get_HW_Prof_Flags_ExA() { PA = cfgmgr32.oCM_Get_HW_Prof_Flags_ExA; runASM(); }
	void fCM_Get_HW_Prof_Flags_ExW() { PA = cfgmgr32.oCM_Get_HW_Prof_Flags_ExW; runASM(); }
	void fCM_Get_Hardware_Profile_InfoA() { PA = cfgmgr32.oCM_Get_Hardware_Profile_InfoA; runASM(); }
	void fCM_Get_Hardware_Profile_InfoW() { PA = cfgmgr32.oCM_Get_Hardware_Profile_InfoW; runASM(); }
	void fCM_Get_Hardware_Profile_Info_ExA() { PA = cfgmgr32.oCM_Get_Hardware_Profile_Info_ExA; runASM(); }
	void fCM_Get_Hardware_Profile_Info_ExW() { PA = cfgmgr32.oCM_Get_Hardware_Profile_Info_ExW; runASM(); }
	void fCM_Get_Log_Conf_Priority() { PA = cfgmgr32.oCM_Get_Log_Conf_Priority; runASM(); }
	void fCM_Get_Log_Conf_Priority_Ex() { PA = cfgmgr32.oCM_Get_Log_Conf_Priority_Ex; runASM(); }
	void fCM_Get_Next_Log_Conf() { PA = cfgmgr32.oCM_Get_Next_Log_Conf; runASM(); }
	void fCM_Get_Next_Log_Conf_Ex() { PA = cfgmgr32.oCM_Get_Next_Log_Conf_Ex; runASM(); }
	void fCM_Get_Next_Res_Des() { PA = cfgmgr32.oCM_Get_Next_Res_Des; runASM(); }
	void fCM_Get_Next_Res_Des_Ex() { PA = cfgmgr32.oCM_Get_Next_Res_Des_Ex; runASM(); }
	void fCM_Get_Parent() { PA = cfgmgr32.oCM_Get_Parent; runASM(); }
	void fCM_Get_Parent_Ex() { PA = cfgmgr32.oCM_Get_Parent_Ex; runASM(); }
	void fCM_Get_Res_Des_Data() { PA = cfgmgr32.oCM_Get_Res_Des_Data; runASM(); }
	void fCM_Get_Res_Des_Data_Ex() { PA = cfgmgr32.oCM_Get_Res_Des_Data_Ex; runASM(); }
	void fCM_Get_Res_Des_Data_Size() { PA = cfgmgr32.oCM_Get_Res_Des_Data_Size; runASM(); }
	void fCM_Get_Res_Des_Data_Size_Ex() { PA = cfgmgr32.oCM_Get_Res_Des_Data_Size_Ex; runASM(); }
	void fCM_Get_Resource_Conflict_Count() { PA = cfgmgr32.oCM_Get_Resource_Conflict_Count; runASM(); }
	void fCM_Get_Resource_Conflict_DetailsA() { PA = cfgmgr32.oCM_Get_Resource_Conflict_DetailsA; runASM(); }
	void fCM_Get_Resource_Conflict_DetailsW() { PA = cfgmgr32.oCM_Get_Resource_Conflict_DetailsW; runASM(); }
	void fCM_Get_Sibling() { PA = cfgmgr32.oCM_Get_Sibling; runASM(); }
	void fCM_Get_Sibling_Ex() { PA = cfgmgr32.oCM_Get_Sibling_Ex; runASM(); }
	void fCM_Get_Version() { PA = cfgmgr32.oCM_Get_Version; runASM(); }
	void fCM_Get_Version_Ex() { PA = cfgmgr32.oCM_Get_Version_Ex; runASM(); }
	void fCM_Import_PowerScheme() { PA = cfgmgr32.oCM_Import_PowerScheme; runASM(); }
	void fCM_Install_DevNodeW() { PA = cfgmgr32.oCM_Install_DevNodeW; runASM(); }
	void fCM_Install_DevNode_ExW() { PA = cfgmgr32.oCM_Install_DevNode_ExW; runASM(); }
	void fCM_Install_DriverW() { PA = cfgmgr32.oCM_Install_DriverW; runASM(); }
	void fCM_Intersect_Range_List() { PA = cfgmgr32.oCM_Intersect_Range_List; runASM(); }
	void fCM_Invert_Range_List() { PA = cfgmgr32.oCM_Invert_Range_List; runASM(); }
	void fCM_Is_Dock_Station_Present() { PA = cfgmgr32.oCM_Is_Dock_Station_Present; runASM(); }
	void fCM_Is_Dock_Station_Present_Ex() { PA = cfgmgr32.oCM_Is_Dock_Station_Present_Ex; runASM(); }
	void fCM_Is_Version_Available() { PA = cfgmgr32.oCM_Is_Version_Available; runASM(); }
	void fCM_Is_Version_Available_Ex() { PA = cfgmgr32.oCM_Is_Version_Available_Ex; runASM(); }
	void fCM_Locate_DevNodeA() { PA = cfgmgr32.oCM_Locate_DevNodeA; runASM(); }
	void fCM_Locate_DevNodeW() { PA = cfgmgr32.oCM_Locate_DevNodeW; runASM(); }
	void fCM_Locate_DevNode_ExA() { PA = cfgmgr32.oCM_Locate_DevNode_ExA; runASM(); }
	void fCM_Locate_DevNode_ExW() { PA = cfgmgr32.oCM_Locate_DevNode_ExW; runASM(); }
	void fCM_MapCrToSpErr() { PA = cfgmgr32.oCM_MapCrToSpErr; runASM(); }
	void fCM_MapCrToWin32Err() { PA = cfgmgr32.oCM_MapCrToWin32Err; runASM(); }
	void fCM_Merge_Range_List() { PA = cfgmgr32.oCM_Merge_Range_List; runASM(); }
	void fCM_Modify_Res_Des() { PA = cfgmgr32.oCM_Modify_Res_Des; runASM(); }
	void fCM_Modify_Res_Des_Ex() { PA = cfgmgr32.oCM_Modify_Res_Des_Ex; runASM(); }
	void fCM_Move_DevNode() { PA = cfgmgr32.oCM_Move_DevNode; runASM(); }
	void fCM_Move_DevNode_Ex() { PA = cfgmgr32.oCM_Move_DevNode_Ex; runASM(); }
	void fCM_Next_Range() { PA = cfgmgr32.oCM_Next_Range; runASM(); }
	void fCM_Open_Class_KeyA() { PA = cfgmgr32.oCM_Open_Class_KeyA; runASM(); }
	void fCM_Open_Class_KeyW() { PA = cfgmgr32.oCM_Open_Class_KeyW; runASM(); }
	void fCM_Open_Class_Key_ExA() { PA = cfgmgr32.oCM_Open_Class_Key_ExA; runASM(); }
	void fCM_Open_Class_Key_ExW() { PA = cfgmgr32.oCM_Open_Class_Key_ExW; runASM(); }
	void fCM_Open_DevNode_Key() { PA = cfgmgr32.oCM_Open_DevNode_Key; runASM(); }
	void fCM_Open_DevNode_Key_Ex() { PA = cfgmgr32.oCM_Open_DevNode_Key_Ex; runASM(); }
	void fCM_Open_Device_Interface_KeyA() { PA = cfgmgr32.oCM_Open_Device_Interface_KeyA; runASM(); }
	void fCM_Open_Device_Interface_KeyW() { PA = cfgmgr32.oCM_Open_Device_Interface_KeyW; runASM(); }
	void fCM_Open_Device_Interface_Key_ExA() { PA = cfgmgr32.oCM_Open_Device_Interface_Key_ExA; runASM(); }
	void fCM_Open_Device_Interface_Key_ExW() { PA = cfgmgr32.oCM_Open_Device_Interface_Key_ExW; runASM(); }
	void fCM_Query_And_Remove_SubTreeA() { PA = cfgmgr32.oCM_Query_And_Remove_SubTreeA; runASM(); }
	void fCM_Query_And_Remove_SubTreeW() { PA = cfgmgr32.oCM_Query_And_Remove_SubTreeW; runASM(); }
	void fCM_Query_And_Remove_SubTree_ExA() { PA = cfgmgr32.oCM_Query_And_Remove_SubTree_ExA; runASM(); }
	void fCM_Query_And_Remove_SubTree_ExW() { PA = cfgmgr32.oCM_Query_And_Remove_SubTree_ExW; runASM(); }
	void fCM_Query_Arbitrator_Free_Data() { PA = cfgmgr32.oCM_Query_Arbitrator_Free_Data; runASM(); }
	void fCM_Query_Arbitrator_Free_Data_Ex() { PA = cfgmgr32.oCM_Query_Arbitrator_Free_Data_Ex; runASM(); }
	void fCM_Query_Arbitrator_Free_Size() { PA = cfgmgr32.oCM_Query_Arbitrator_Free_Size; runASM(); }
	void fCM_Query_Arbitrator_Free_Size_Ex() { PA = cfgmgr32.oCM_Query_Arbitrator_Free_Size_Ex; runASM(); }
	void fCM_Query_Remove_SubTree() { PA = cfgmgr32.oCM_Query_Remove_SubTree; runASM(); }
	void fCM_Query_Remove_SubTree_Ex() { PA = cfgmgr32.oCM_Query_Remove_SubTree_Ex; runASM(); }
	void fCM_Query_Resource_Conflict_List() { PA = cfgmgr32.oCM_Query_Resource_Conflict_List; runASM(); }
	void fCM_Reenumerate_DevNode() { PA = cfgmgr32.oCM_Reenumerate_DevNode; runASM(); }
	void fCM_Reenumerate_DevNode_Ex() { PA = cfgmgr32.oCM_Reenumerate_DevNode_Ex; runASM(); }
	void fCM_Register_Device_Driver() { PA = cfgmgr32.oCM_Register_Device_Driver; runASM(); }
	void fCM_Register_Device_Driver_Ex() { PA = cfgmgr32.oCM_Register_Device_Driver_Ex; runASM(); }
	void fCM_Register_Device_InterfaceA() { PA = cfgmgr32.oCM_Register_Device_InterfaceA; runASM(); }
	void fCM_Register_Device_InterfaceW() { PA = cfgmgr32.oCM_Register_Device_InterfaceW; runASM(); }
	void fCM_Register_Device_Interface_ExA() { PA = cfgmgr32.oCM_Register_Device_Interface_ExA; runASM(); }
	void fCM_Register_Device_Interface_ExW() { PA = cfgmgr32.oCM_Register_Device_Interface_ExW; runASM(); }
	//void fCM_Register_Notification() { PA = cfgmgr32.oCM_Register_Notification; runASM(); }
	//void fCM_Register_Notification() { return CR_SUCCESS; }
	CONFIGRET WINAPI fCM_Register_Notification(PCM_NOTIFY_FILTER pFilter, PVOID pContext, PCM_NOTIFY_CALLBACK pCallback, PHCMNOTIFICATION pNotifyContext) { return CR_SUCCESS; }
	void fCM_Remove_SubTree() { PA = cfgmgr32.oCM_Remove_SubTree; runASM(); }
	void fCM_Remove_SubTree_Ex() { PA = cfgmgr32.oCM_Remove_SubTree_Ex; runASM(); }
	void fCM_Request_Device_EjectA() { PA = cfgmgr32.oCM_Request_Device_EjectA; runASM(); }
	void fCM_Request_Device_EjectW() { PA = cfgmgr32.oCM_Request_Device_EjectW; runASM(); }
	void fCM_Request_Device_Eject_ExA() { PA = cfgmgr32.oCM_Request_Device_Eject_ExA; runASM(); }
	void fCM_Request_Device_Eject_ExW() { PA = cfgmgr32.oCM_Request_Device_Eject_ExW; runASM(); }
	void fCM_Request_Eject_PC() { PA = cfgmgr32.oCM_Request_Eject_PC; runASM(); }
	void fCM_Request_Eject_PC_Ex() { PA = cfgmgr32.oCM_Request_Eject_PC_Ex; runASM(); }
	void fCM_RestoreAll_DefaultPowerSchemes() { PA = cfgmgr32.oCM_RestoreAll_DefaultPowerSchemes; runASM(); }
	void fCM_Restore_DefaultPowerScheme() { PA = cfgmgr32.oCM_Restore_DefaultPowerScheme; runASM(); }
	void fCM_Run_Detection() { PA = cfgmgr32.oCM_Run_Detection; runASM(); }
	void fCM_Run_Detection_Ex() { PA = cfgmgr32.oCM_Run_Detection_Ex; runASM(); }
	void fCM_Set_ActiveScheme() { PA = cfgmgr32.oCM_Set_ActiveScheme; runASM(); }
	void fCM_Set_Class_PropertyW() { PA = cfgmgr32.oCM_Set_Class_PropertyW; runASM(); }
	void fCM_Set_Class_Property_ExW() { PA = cfgmgr32.oCM_Set_Class_Property_ExW; runASM(); }
	void fCM_Set_Class_Registry_PropertyA() { PA = cfgmgr32.oCM_Set_Class_Registry_PropertyA; runASM(); }
	void fCM_Set_Class_Registry_PropertyW() { PA = cfgmgr32.oCM_Set_Class_Registry_PropertyW; runASM(); }
	void fCM_Set_DevNode_Problem() { PA = cfgmgr32.oCM_Set_DevNode_Problem; runASM(); }
	void fCM_Set_DevNode_Problem_Ex() { PA = cfgmgr32.oCM_Set_DevNode_Problem_Ex; runASM(); }
	void fCM_Set_DevNode_PropertyW() { PA = cfgmgr32.oCM_Set_DevNode_PropertyW; runASM(); }
	void fCM_Set_DevNode_Property_ExW() { PA = cfgmgr32.oCM_Set_DevNode_Property_ExW; runASM(); }
	void fCM_Set_DevNode_Registry_PropertyA() { PA = cfgmgr32.oCM_Set_DevNode_Registry_PropertyA; runASM(); }
	void fCM_Set_DevNode_Registry_PropertyW() { PA = cfgmgr32.oCM_Set_DevNode_Registry_PropertyW; runASM(); }
	void fCM_Set_DevNode_Registry_Property_ExA() { PA = cfgmgr32.oCM_Set_DevNode_Registry_Property_ExA; runASM(); }
	void fCM_Set_DevNode_Registry_Property_ExW() { PA = cfgmgr32.oCM_Set_DevNode_Registry_Property_ExW; runASM(); }
	void fCM_Set_Device_Interface_PropertyW() { PA = cfgmgr32.oCM_Set_Device_Interface_PropertyW; runASM(); }
	void fCM_Set_Device_Interface_Property_ExW() { PA = cfgmgr32.oCM_Set_Device_Interface_Property_ExW; runASM(); }
	void fCM_Set_HW_Prof() { PA = cfgmgr32.oCM_Set_HW_Prof; runASM(); }
	void fCM_Set_HW_Prof_Ex() { PA = cfgmgr32.oCM_Set_HW_Prof_Ex; runASM(); }
	void fCM_Set_HW_Prof_FlagsA() { PA = cfgmgr32.oCM_Set_HW_Prof_FlagsA; runASM(); }
	void fCM_Set_HW_Prof_FlagsW() { PA = cfgmgr32.oCM_Set_HW_Prof_FlagsW; runASM(); }
	void fCM_Set_HW_Prof_Flags_ExA() { PA = cfgmgr32.oCM_Set_HW_Prof_Flags_ExA; runASM(); }
	void fCM_Set_HW_Prof_Flags_ExW() { PA = cfgmgr32.oCM_Set_HW_Prof_Flags_ExW; runASM(); }
	void fCM_Setup_DevNode() { PA = cfgmgr32.oCM_Setup_DevNode; runASM(); }
	void fCM_Setup_DevNode_Ex() { PA = cfgmgr32.oCM_Setup_DevNode_Ex; runASM(); }
	void fCM_Test_Range_Available() { PA = cfgmgr32.oCM_Test_Range_Available; runASM(); }
	void fCM_Uninstall_DevNode() { PA = cfgmgr32.oCM_Uninstall_DevNode; runASM(); }
	void fCM_Uninstall_DevNode_Ex() { PA = cfgmgr32.oCM_Uninstall_DevNode_Ex; runASM(); }
	void fCM_Uninstall_DriverW() { PA = cfgmgr32.oCM_Uninstall_DriverW; runASM(); }
	void fCM_Unregister_Device_InterfaceA() { PA = cfgmgr32.oCM_Unregister_Device_InterfaceA; runASM(); }
	void fCM_Unregister_Device_InterfaceW() { PA = cfgmgr32.oCM_Unregister_Device_InterfaceW; runASM(); }
	void fCM_Unregister_Device_Interface_ExA() { PA = cfgmgr32.oCM_Unregister_Device_Interface_ExA; runASM(); }
	void fCM_Unregister_Device_Interface_ExW() { PA = cfgmgr32.oCM_Unregister_Device_Interface_ExW; runASM(); }
	void fCM_Unregister_Notification() { PA = cfgmgr32.oCM_Unregister_Notification; runASM(); }
	void fCM_Write_UserPowerKey() { PA = cfgmgr32.oCM_Write_UserPowerKey; runASM(); }
	void fDevCloseObjectQuery() { PA = cfgmgr32.oDevCloseObjectQuery; runASM(); }
	void fDevCreateObjectQuery() { PA = cfgmgr32.oDevCreateObjectQuery; runASM(); }
	void fDevCreateObjectQueryEx() { PA = cfgmgr32.oDevCreateObjectQueryEx; runASM(); }
	void fDevCreateObjectQueryFromId() { PA = cfgmgr32.oDevCreateObjectQueryFromId; runASM(); }
	void fDevCreateObjectQueryFromIdEx() { PA = cfgmgr32.oDevCreateObjectQueryFromIdEx; runASM(); }
	void fDevCreateObjectQueryFromIds() { PA = cfgmgr32.oDevCreateObjectQueryFromIds; runASM(); }
	void fDevCreateObjectQueryFromIdsEx() { PA = cfgmgr32.oDevCreateObjectQueryFromIdsEx; runASM(); }
	void fDevFindProperty() { PA = cfgmgr32.oDevFindProperty; runASM(); }
	void fDevFreeObjectProperties() { PA = cfgmgr32.oDevFreeObjectProperties; runASM(); }
	void fDevFreeObjects() { PA = cfgmgr32.oDevFreeObjects; runASM(); }
	void fDevGetObjectProperties() { PA = cfgmgr32.oDevGetObjectProperties; runASM(); }
	void fDevGetObjectPropertiesEx() { PA = cfgmgr32.oDevGetObjectPropertiesEx; runASM(); }
	void fDevGetObjects() { PA = cfgmgr32.oDevGetObjects; runASM(); }
	void fDevGetObjectsEx() { PA = cfgmgr32.oDevGetObjectsEx; runASM(); }
	void fDevSetObjectProperties() { PA = cfgmgr32.oDevSetObjectProperties; runASM(); }
	void fSwDeviceClose() { PA = cfgmgr32.oSwDeviceClose; runASM(); }
	void fSwDeviceCreate() { PA = cfgmgr32.oSwDeviceCreate; runASM(); }
	void fSwDeviceGetLifetime() { PA = cfgmgr32.oSwDeviceGetLifetime; runASM(); }
	void fSwDeviceInterfacePropertySet() { PA = cfgmgr32.oSwDeviceInterfacePropertySet; runASM(); }
	void fSwDeviceInterfaceRegister() { PA = cfgmgr32.oSwDeviceInterfaceRegister; runASM(); }
	void fSwDeviceInterfaceSetState() { PA = cfgmgr32.oSwDeviceInterfaceSetState; runASM(); }
	void fSwDevicePropertySet() { PA = cfgmgr32.oSwDevicePropertySet; runASM(); }
	void fSwDeviceSetLifetime() { PA = cfgmgr32.oSwDeviceSetLifetime; runASM(); }
	void fSwMemFree() { PA = cfgmgr32.oSwMemFree; runASM(); }
}

void setupFunctions() {
	cfgmgr32.oCMP_GetBlockedDriverInfo = GetProcAddress(cfgmgr32.dll, "CMP_GetBlockedDriverInfo");
	cfgmgr32.oCMP_GetServerSideDeviceInstallFlags = GetProcAddress(cfgmgr32.dll, "CMP_GetServerSideDeviceInstallFlags");
	cfgmgr32.oCMP_Init_Detection = GetProcAddress(cfgmgr32.dll, "CMP_Init_Detection");
	cfgmgr32.oCMP_RegisterServiceNotification = GetProcAddress(cfgmgr32.dll, "CMP_RegisterServiceNotification");
	cfgmgr32.oCMP_Register_Notification = GetProcAddress(cfgmgr32.dll, "CMP_Register_Notification");
	cfgmgr32.oCMP_Report_LogOn = GetProcAddress(cfgmgr32.dll, "CMP_Report_LogOn");
	cfgmgr32.oCMP_WaitNoPendingInstallEvents = GetProcAddress(cfgmgr32.dll, "CMP_WaitNoPendingInstallEvents");
	cfgmgr32.oCMP_WaitServicesAvailable = GetProcAddress(cfgmgr32.dll, "CMP_WaitServicesAvailable");
	cfgmgr32.oCM_Add_Driver_PackageW = GetProcAddress(cfgmgr32.dll, "CM_Add_Driver_PackageW");
	cfgmgr32.oCM_Add_Driver_Package_ExW = GetProcAddress(cfgmgr32.dll, "CM_Add_Driver_Package_ExW");
	cfgmgr32.oCM_Add_Empty_Log_Conf = GetProcAddress(cfgmgr32.dll, "CM_Add_Empty_Log_Conf");
	cfgmgr32.oCM_Add_Empty_Log_Conf_Ex = GetProcAddress(cfgmgr32.dll, "CM_Add_Empty_Log_Conf_Ex");
	cfgmgr32.oCM_Add_IDA = GetProcAddress(cfgmgr32.dll, "CM_Add_IDA");
	cfgmgr32.oCM_Add_IDW = GetProcAddress(cfgmgr32.dll, "CM_Add_IDW");
	cfgmgr32.oCM_Add_ID_ExA = GetProcAddress(cfgmgr32.dll, "CM_Add_ID_ExA");
	cfgmgr32.oCM_Add_ID_ExW = GetProcAddress(cfgmgr32.dll, "CM_Add_ID_ExW");
	cfgmgr32.oCM_Add_Range = GetProcAddress(cfgmgr32.dll, "CM_Add_Range");
	cfgmgr32.oCM_Add_Res_Des = GetProcAddress(cfgmgr32.dll, "CM_Add_Res_Des");
	cfgmgr32.oCM_Add_Res_Des_Ex = GetProcAddress(cfgmgr32.dll, "CM_Add_Res_Des_Ex");
	cfgmgr32.oCM_Apply_PowerScheme = GetProcAddress(cfgmgr32.dll, "CM_Apply_PowerScheme");
	cfgmgr32.oCM_Connect_MachineA = GetProcAddress(cfgmgr32.dll, "CM_Connect_MachineA");
	cfgmgr32.oCM_Connect_MachineW = GetProcAddress(cfgmgr32.dll, "CM_Connect_MachineW");
	cfgmgr32.oCM_Create_DevNodeA = GetProcAddress(cfgmgr32.dll, "CM_Create_DevNodeA");
	cfgmgr32.oCM_Create_DevNodeW = GetProcAddress(cfgmgr32.dll, "CM_Create_DevNodeW");
	cfgmgr32.oCM_Create_DevNode_ExA = GetProcAddress(cfgmgr32.dll, "CM_Create_DevNode_ExA");
	cfgmgr32.oCM_Create_DevNode_ExW = GetProcAddress(cfgmgr32.dll, "CM_Create_DevNode_ExW");
	cfgmgr32.oCM_Create_Range_List = GetProcAddress(cfgmgr32.dll, "CM_Create_Range_List");
	cfgmgr32.oCM_Delete_Class_Key = GetProcAddress(cfgmgr32.dll, "CM_Delete_Class_Key");
	cfgmgr32.oCM_Delete_Class_Key_Ex = GetProcAddress(cfgmgr32.dll, "CM_Delete_Class_Key_Ex");
	cfgmgr32.oCM_Delete_DevNode_Key = GetProcAddress(cfgmgr32.dll, "CM_Delete_DevNode_Key");
	cfgmgr32.oCM_Delete_DevNode_Key_Ex = GetProcAddress(cfgmgr32.dll, "CM_Delete_DevNode_Key_Ex");
	cfgmgr32.oCM_Delete_Device_Interface_KeyA = GetProcAddress(cfgmgr32.dll, "CM_Delete_Device_Interface_KeyA");
	cfgmgr32.oCM_Delete_Device_Interface_KeyW = GetProcAddress(cfgmgr32.dll, "CM_Delete_Device_Interface_KeyW");
	cfgmgr32.oCM_Delete_Device_Interface_Key_ExA = GetProcAddress(cfgmgr32.dll, "CM_Delete_Device_Interface_Key_ExA");
	cfgmgr32.oCM_Delete_Device_Interface_Key_ExW = GetProcAddress(cfgmgr32.dll, "CM_Delete_Device_Interface_Key_ExW");
	cfgmgr32.oCM_Delete_Driver_PackageW = GetProcAddress(cfgmgr32.dll, "CM_Delete_Driver_PackageW");
	cfgmgr32.oCM_Delete_Driver_Package_ExW = GetProcAddress(cfgmgr32.dll, "CM_Delete_Driver_Package_ExW");
	cfgmgr32.oCM_Delete_PowerScheme = GetProcAddress(cfgmgr32.dll, "CM_Delete_PowerScheme");
	cfgmgr32.oCM_Delete_Range = GetProcAddress(cfgmgr32.dll, "CM_Delete_Range");
	cfgmgr32.oCM_Detect_Resource_Conflict = GetProcAddress(cfgmgr32.dll, "CM_Detect_Resource_Conflict");
	cfgmgr32.oCM_Detect_Resource_Conflict_Ex = GetProcAddress(cfgmgr32.dll, "CM_Detect_Resource_Conflict_Ex");
	cfgmgr32.oCM_Disable_DevNode = GetProcAddress(cfgmgr32.dll, "CM_Disable_DevNode");
	cfgmgr32.oCM_Disable_DevNode_Ex = GetProcAddress(cfgmgr32.dll, "CM_Disable_DevNode_Ex");
	cfgmgr32.oCM_Disconnect_Machine = GetProcAddress(cfgmgr32.dll, "CM_Disconnect_Machine");
	cfgmgr32.oCM_Dup_Range_List = GetProcAddress(cfgmgr32.dll, "CM_Dup_Range_List");
	cfgmgr32.oCM_Duplicate_PowerScheme = GetProcAddress(cfgmgr32.dll, "CM_Duplicate_PowerScheme");
	cfgmgr32.oCM_Enable_DevNode = GetProcAddress(cfgmgr32.dll, "CM_Enable_DevNode");
	cfgmgr32.oCM_Enable_DevNode_Ex = GetProcAddress(cfgmgr32.dll, "CM_Enable_DevNode_Ex");
	cfgmgr32.oCM_Enumerate_Classes = GetProcAddress(cfgmgr32.dll, "CM_Enumerate_Classes");
	cfgmgr32.oCM_Enumerate_Classes_Ex = GetProcAddress(cfgmgr32.dll, "CM_Enumerate_Classes_Ex");
	cfgmgr32.oCM_Enumerate_EnumeratorsA = GetProcAddress(cfgmgr32.dll, "CM_Enumerate_EnumeratorsA");
	cfgmgr32.oCM_Enumerate_EnumeratorsW = GetProcAddress(cfgmgr32.dll, "CM_Enumerate_EnumeratorsW");
	cfgmgr32.oCM_Enumerate_Enumerators_ExA = GetProcAddress(cfgmgr32.dll, "CM_Enumerate_Enumerators_ExA");
	cfgmgr32.oCM_Enumerate_Enumerators_ExW = GetProcAddress(cfgmgr32.dll, "CM_Enumerate_Enumerators_ExW");
	cfgmgr32.oCM_Find_Range = GetProcAddress(cfgmgr32.dll, "CM_Find_Range");
	cfgmgr32.oCM_First_Range = GetProcAddress(cfgmgr32.dll, "CM_First_Range");
	cfgmgr32.oCM_Free_Log_Conf = GetProcAddress(cfgmgr32.dll, "CM_Free_Log_Conf");
	cfgmgr32.oCM_Free_Log_Conf_Ex = GetProcAddress(cfgmgr32.dll, "CM_Free_Log_Conf_Ex");
	cfgmgr32.oCM_Free_Log_Conf_Handle = GetProcAddress(cfgmgr32.dll, "CM_Free_Log_Conf_Handle");
	cfgmgr32.oCM_Free_Range_List = GetProcAddress(cfgmgr32.dll, "CM_Free_Range_List");
	cfgmgr32.oCM_Free_Res_Des = GetProcAddress(cfgmgr32.dll, "CM_Free_Res_Des");
	cfgmgr32.oCM_Free_Res_Des_Ex = GetProcAddress(cfgmgr32.dll, "CM_Free_Res_Des_Ex");
	cfgmgr32.oCM_Free_Res_Des_Handle = GetProcAddress(cfgmgr32.dll, "CM_Free_Res_Des_Handle");
	cfgmgr32.oCM_Free_Resource_Conflict_Handle = GetProcAddress(cfgmgr32.dll, "CM_Free_Resource_Conflict_Handle");
	cfgmgr32.oCM_Get_Child = GetProcAddress(cfgmgr32.dll, "CM_Get_Child");
	cfgmgr32.oCM_Get_Child_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Child_Ex");
	cfgmgr32.oCM_Get_Class_Key_NameA = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_Key_NameA");
	cfgmgr32.oCM_Get_Class_Key_NameW = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_Key_NameW");
	cfgmgr32.oCM_Get_Class_Key_Name_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_Key_Name_ExA");
	cfgmgr32.oCM_Get_Class_Key_Name_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_Key_Name_ExW");
	cfgmgr32.oCM_Get_Class_NameA = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_NameA");
	cfgmgr32.oCM_Get_Class_NameW = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_NameW");
	cfgmgr32.oCM_Get_Class_Name_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_Name_ExA");
	cfgmgr32.oCM_Get_Class_Name_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_Name_ExW");
	cfgmgr32.oCM_Get_Class_PropertyW = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_PropertyW");
	cfgmgr32.oCM_Get_Class_Property_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_Property_ExW");
	cfgmgr32.oCM_Get_Class_Property_Keys = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_Property_Keys");
	cfgmgr32.oCM_Get_Class_Property_Keys_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_Property_Keys_Ex");
	cfgmgr32.oCM_Get_Class_Registry_PropertyA = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_Registry_PropertyA");
	cfgmgr32.oCM_Get_Class_Registry_PropertyW = GetProcAddress(cfgmgr32.dll, "CM_Get_Class_Registry_PropertyW");
	cfgmgr32.oCM_Get_Depth = GetProcAddress(cfgmgr32.dll, "CM_Get_Depth");
	cfgmgr32.oCM_Get_Depth_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Depth_Ex");
	cfgmgr32.oCM_Get_DevNode_Custom_PropertyA = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Custom_PropertyA");
	cfgmgr32.oCM_Get_DevNode_Custom_PropertyW = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Custom_PropertyW");
	cfgmgr32.oCM_Get_DevNode_Custom_Property_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Custom_Property_ExA");
	cfgmgr32.oCM_Get_DevNode_Custom_Property_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Custom_Property_ExW");
	cfgmgr32.oCM_Get_DevNode_PropertyW = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_PropertyW");
	cfgmgr32.oCM_Get_DevNode_Property_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Property_ExW");
	cfgmgr32.oCM_Get_DevNode_Property_Keys = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Property_Keys");
	cfgmgr32.oCM_Get_DevNode_Property_Keys_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Property_Keys_Ex");
	cfgmgr32.oCM_Get_DevNode_Registry_PropertyA = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Registry_PropertyA");
	cfgmgr32.oCM_Get_DevNode_Registry_PropertyW = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Registry_PropertyW");
	cfgmgr32.oCM_Get_DevNode_Registry_Property_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Registry_Property_ExA");
	cfgmgr32.oCM_Get_DevNode_Registry_Property_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Registry_Property_ExW");
	cfgmgr32.oCM_Get_DevNode_Status = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Status");
	cfgmgr32.oCM_Get_DevNode_Status_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_DevNode_Status_Ex");
	cfgmgr32.oCM_Get_Device_IDA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_IDA");
	cfgmgr32.oCM_Get_Device_IDW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_IDW");
	cfgmgr32.oCM_Get_Device_ID_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_ExA");
	cfgmgr32.oCM_Get_Device_ID_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_ExW");
	cfgmgr32.oCM_Get_Device_ID_ListA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_ListA");
	cfgmgr32.oCM_Get_Device_ID_ListW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_ListW");
	cfgmgr32.oCM_Get_Device_ID_List_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_List_ExA");
	cfgmgr32.oCM_Get_Device_ID_List_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_List_ExW");
	cfgmgr32.oCM_Get_Device_ID_List_SizeA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_List_SizeA");
	cfgmgr32.oCM_Get_Device_ID_List_SizeW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_List_SizeW");
	cfgmgr32.oCM_Get_Device_ID_List_Size_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_List_Size_ExA");
	cfgmgr32.oCM_Get_Device_ID_List_Size_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_List_Size_ExW");
	cfgmgr32.oCM_Get_Device_ID_Size = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_Size");
	cfgmgr32.oCM_Get_Device_ID_Size_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_ID_Size_Ex");
	cfgmgr32.oCM_Get_Device_Interface_AliasA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_AliasA");
	cfgmgr32.oCM_Get_Device_Interface_AliasW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_AliasW");
	cfgmgr32.oCM_Get_Device_Interface_Alias_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_Alias_ExA");
	cfgmgr32.oCM_Get_Device_Interface_Alias_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_Alias_ExW");
	cfgmgr32.oCM_Get_Device_Interface_ListA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_ListA");
	cfgmgr32.oCM_Get_Device_Interface_ListW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_ListW");
	cfgmgr32.oCM_Get_Device_Interface_List_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_List_ExA");
	cfgmgr32.oCM_Get_Device_Interface_List_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_List_ExW");
	cfgmgr32.oCM_Get_Device_Interface_List_SizeA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_List_SizeA");
	cfgmgr32.oCM_Get_Device_Interface_List_SizeW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_List_SizeW");
	cfgmgr32.oCM_Get_Device_Interface_List_Size_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_List_Size_ExA");
	cfgmgr32.oCM_Get_Device_Interface_List_Size_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_List_Size_ExW");
	cfgmgr32.oCM_Get_Device_Interface_PropertyW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_PropertyW");
	cfgmgr32.oCM_Get_Device_Interface_Property_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_Property_ExW");
	cfgmgr32.oCM_Get_Device_Interface_Property_KeysW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_Property_KeysW");
	cfgmgr32.oCM_Get_Device_Interface_Property_Keys_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Device_Interface_Property_Keys_ExW");
	cfgmgr32.oCM_Get_First_Log_Conf = GetProcAddress(cfgmgr32.dll, "CM_Get_First_Log_Conf");
	cfgmgr32.oCM_Get_First_Log_Conf_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_First_Log_Conf_Ex");
	cfgmgr32.oCM_Get_Global_State = GetProcAddress(cfgmgr32.dll, "CM_Get_Global_State");
	cfgmgr32.oCM_Get_Global_State_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Global_State_Ex");
	cfgmgr32.oCM_Get_HW_Prof_FlagsA = GetProcAddress(cfgmgr32.dll, "CM_Get_HW_Prof_FlagsA");
	cfgmgr32.oCM_Get_HW_Prof_FlagsW = GetProcAddress(cfgmgr32.dll, "CM_Get_HW_Prof_FlagsW");
	cfgmgr32.oCM_Get_HW_Prof_Flags_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_HW_Prof_Flags_ExA");
	cfgmgr32.oCM_Get_HW_Prof_Flags_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_HW_Prof_Flags_ExW");
	cfgmgr32.oCM_Get_Hardware_Profile_InfoA = GetProcAddress(cfgmgr32.dll, "CM_Get_Hardware_Profile_InfoA");
	cfgmgr32.oCM_Get_Hardware_Profile_InfoW = GetProcAddress(cfgmgr32.dll, "CM_Get_Hardware_Profile_InfoW");
	cfgmgr32.oCM_Get_Hardware_Profile_Info_ExA = GetProcAddress(cfgmgr32.dll, "CM_Get_Hardware_Profile_Info_ExA");
	cfgmgr32.oCM_Get_Hardware_Profile_Info_ExW = GetProcAddress(cfgmgr32.dll, "CM_Get_Hardware_Profile_Info_ExW");
	cfgmgr32.oCM_Get_Log_Conf_Priority = GetProcAddress(cfgmgr32.dll, "CM_Get_Log_Conf_Priority");
	cfgmgr32.oCM_Get_Log_Conf_Priority_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Log_Conf_Priority_Ex");
	cfgmgr32.oCM_Get_Next_Log_Conf = GetProcAddress(cfgmgr32.dll, "CM_Get_Next_Log_Conf");
	cfgmgr32.oCM_Get_Next_Log_Conf_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Next_Log_Conf_Ex");
	cfgmgr32.oCM_Get_Next_Res_Des = GetProcAddress(cfgmgr32.dll, "CM_Get_Next_Res_Des");
	cfgmgr32.oCM_Get_Next_Res_Des_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Next_Res_Des_Ex");
	cfgmgr32.oCM_Get_Parent = GetProcAddress(cfgmgr32.dll, "CM_Get_Parent");
	cfgmgr32.oCM_Get_Parent_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Parent_Ex");
	cfgmgr32.oCM_Get_Res_Des_Data = GetProcAddress(cfgmgr32.dll, "CM_Get_Res_Des_Data");
	cfgmgr32.oCM_Get_Res_Des_Data_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Res_Des_Data_Ex");
	cfgmgr32.oCM_Get_Res_Des_Data_Size = GetProcAddress(cfgmgr32.dll, "CM_Get_Res_Des_Data_Size");
	cfgmgr32.oCM_Get_Res_Des_Data_Size_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Res_Des_Data_Size_Ex");
	cfgmgr32.oCM_Get_Resource_Conflict_Count = GetProcAddress(cfgmgr32.dll, "CM_Get_Resource_Conflict_Count");
	cfgmgr32.oCM_Get_Resource_Conflict_DetailsA = GetProcAddress(cfgmgr32.dll, "CM_Get_Resource_Conflict_DetailsA");
	cfgmgr32.oCM_Get_Resource_Conflict_DetailsW = GetProcAddress(cfgmgr32.dll, "CM_Get_Resource_Conflict_DetailsW");
	cfgmgr32.oCM_Get_Sibling = GetProcAddress(cfgmgr32.dll, "CM_Get_Sibling");
	cfgmgr32.oCM_Get_Sibling_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Sibling_Ex");
	cfgmgr32.oCM_Get_Version = GetProcAddress(cfgmgr32.dll, "CM_Get_Version");
	cfgmgr32.oCM_Get_Version_Ex = GetProcAddress(cfgmgr32.dll, "CM_Get_Version_Ex");
	cfgmgr32.oCM_Import_PowerScheme = GetProcAddress(cfgmgr32.dll, "CM_Import_PowerScheme");
	cfgmgr32.oCM_Install_DevNodeW = GetProcAddress(cfgmgr32.dll, "CM_Install_DevNodeW");
	cfgmgr32.oCM_Install_DevNode_ExW = GetProcAddress(cfgmgr32.dll, "CM_Install_DevNode_ExW");
	cfgmgr32.oCM_Install_DriverW = GetProcAddress(cfgmgr32.dll, "CM_Install_DriverW");
	cfgmgr32.oCM_Intersect_Range_List = GetProcAddress(cfgmgr32.dll, "CM_Intersect_Range_List");
	cfgmgr32.oCM_Invert_Range_List = GetProcAddress(cfgmgr32.dll, "CM_Invert_Range_List");
	cfgmgr32.oCM_Is_Dock_Station_Present = GetProcAddress(cfgmgr32.dll, "CM_Is_Dock_Station_Present");
	cfgmgr32.oCM_Is_Dock_Station_Present_Ex = GetProcAddress(cfgmgr32.dll, "CM_Is_Dock_Station_Present_Ex");
	cfgmgr32.oCM_Is_Version_Available = GetProcAddress(cfgmgr32.dll, "CM_Is_Version_Available");
	cfgmgr32.oCM_Is_Version_Available_Ex = GetProcAddress(cfgmgr32.dll, "CM_Is_Version_Available_Ex");
	cfgmgr32.oCM_Locate_DevNodeA = GetProcAddress(cfgmgr32.dll, "CM_Locate_DevNodeA");
	cfgmgr32.oCM_Locate_DevNodeW = GetProcAddress(cfgmgr32.dll, "CM_Locate_DevNodeW");
	cfgmgr32.oCM_Locate_DevNode_ExA = GetProcAddress(cfgmgr32.dll, "CM_Locate_DevNode_ExA");
	cfgmgr32.oCM_Locate_DevNode_ExW = GetProcAddress(cfgmgr32.dll, "CM_Locate_DevNode_ExW");
	cfgmgr32.oCM_MapCrToSpErr = GetProcAddress(cfgmgr32.dll, "CM_MapCrToSpErr");
	cfgmgr32.oCM_MapCrToWin32Err = GetProcAddress(cfgmgr32.dll, "CM_MapCrToWin32Err");
	cfgmgr32.oCM_Merge_Range_List = GetProcAddress(cfgmgr32.dll, "CM_Merge_Range_List");
	cfgmgr32.oCM_Modify_Res_Des = GetProcAddress(cfgmgr32.dll, "CM_Modify_Res_Des");
	cfgmgr32.oCM_Modify_Res_Des_Ex = GetProcAddress(cfgmgr32.dll, "CM_Modify_Res_Des_Ex");
	cfgmgr32.oCM_Move_DevNode = GetProcAddress(cfgmgr32.dll, "CM_Move_DevNode");
	cfgmgr32.oCM_Move_DevNode_Ex = GetProcAddress(cfgmgr32.dll, "CM_Move_DevNode_Ex");
	cfgmgr32.oCM_Next_Range = GetProcAddress(cfgmgr32.dll, "CM_Next_Range");
	cfgmgr32.oCM_Open_Class_KeyA = GetProcAddress(cfgmgr32.dll, "CM_Open_Class_KeyA");
	cfgmgr32.oCM_Open_Class_KeyW = GetProcAddress(cfgmgr32.dll, "CM_Open_Class_KeyW");
	cfgmgr32.oCM_Open_Class_Key_ExA = GetProcAddress(cfgmgr32.dll, "CM_Open_Class_Key_ExA");
	cfgmgr32.oCM_Open_Class_Key_ExW = GetProcAddress(cfgmgr32.dll, "CM_Open_Class_Key_ExW");
	cfgmgr32.oCM_Open_DevNode_Key = GetProcAddress(cfgmgr32.dll, "CM_Open_DevNode_Key");
	cfgmgr32.oCM_Open_DevNode_Key_Ex = GetProcAddress(cfgmgr32.dll, "CM_Open_DevNode_Key_Ex");
	cfgmgr32.oCM_Open_Device_Interface_KeyA = GetProcAddress(cfgmgr32.dll, "CM_Open_Device_Interface_KeyA");
	cfgmgr32.oCM_Open_Device_Interface_KeyW = GetProcAddress(cfgmgr32.dll, "CM_Open_Device_Interface_KeyW");
	cfgmgr32.oCM_Open_Device_Interface_Key_ExA = GetProcAddress(cfgmgr32.dll, "CM_Open_Device_Interface_Key_ExA");
	cfgmgr32.oCM_Open_Device_Interface_Key_ExW = GetProcAddress(cfgmgr32.dll, "CM_Open_Device_Interface_Key_ExW");
	cfgmgr32.oCM_Query_And_Remove_SubTreeA = GetProcAddress(cfgmgr32.dll, "CM_Query_And_Remove_SubTreeA");
	cfgmgr32.oCM_Query_And_Remove_SubTreeW = GetProcAddress(cfgmgr32.dll, "CM_Query_And_Remove_SubTreeW");
	cfgmgr32.oCM_Query_And_Remove_SubTree_ExA = GetProcAddress(cfgmgr32.dll, "CM_Query_And_Remove_SubTree_ExA");
	cfgmgr32.oCM_Query_And_Remove_SubTree_ExW = GetProcAddress(cfgmgr32.dll, "CM_Query_And_Remove_SubTree_ExW");
	cfgmgr32.oCM_Query_Arbitrator_Free_Data = GetProcAddress(cfgmgr32.dll, "CM_Query_Arbitrator_Free_Data");
	cfgmgr32.oCM_Query_Arbitrator_Free_Data_Ex = GetProcAddress(cfgmgr32.dll, "CM_Query_Arbitrator_Free_Data_Ex");
	cfgmgr32.oCM_Query_Arbitrator_Free_Size = GetProcAddress(cfgmgr32.dll, "CM_Query_Arbitrator_Free_Size");
	cfgmgr32.oCM_Query_Arbitrator_Free_Size_Ex = GetProcAddress(cfgmgr32.dll, "CM_Query_Arbitrator_Free_Size_Ex");
	cfgmgr32.oCM_Query_Remove_SubTree = GetProcAddress(cfgmgr32.dll, "CM_Query_Remove_SubTree");
	cfgmgr32.oCM_Query_Remove_SubTree_Ex = GetProcAddress(cfgmgr32.dll, "CM_Query_Remove_SubTree_Ex");
	cfgmgr32.oCM_Query_Resource_Conflict_List = GetProcAddress(cfgmgr32.dll, "CM_Query_Resource_Conflict_List");
	cfgmgr32.oCM_Reenumerate_DevNode = GetProcAddress(cfgmgr32.dll, "CM_Reenumerate_DevNode");
	cfgmgr32.oCM_Reenumerate_DevNode_Ex = GetProcAddress(cfgmgr32.dll, "CM_Reenumerate_DevNode_Ex");
	cfgmgr32.oCM_Register_Device_Driver = GetProcAddress(cfgmgr32.dll, "CM_Register_Device_Driver");
	cfgmgr32.oCM_Register_Device_Driver_Ex = GetProcAddress(cfgmgr32.dll, "CM_Register_Device_Driver_Ex");
	cfgmgr32.oCM_Register_Device_InterfaceA = GetProcAddress(cfgmgr32.dll, "CM_Register_Device_InterfaceA");
	cfgmgr32.oCM_Register_Device_InterfaceW = GetProcAddress(cfgmgr32.dll, "CM_Register_Device_InterfaceW");
	cfgmgr32.oCM_Register_Device_Interface_ExA = GetProcAddress(cfgmgr32.dll, "CM_Register_Device_Interface_ExA");
	cfgmgr32.oCM_Register_Device_Interface_ExW = GetProcAddress(cfgmgr32.dll, "CM_Register_Device_Interface_ExW");
	//cfgmgr32.oCM_Register_Notification = GetProcAddress(cfgmgr32.dll, "CM_Register_Notification");
	//cfgmgr32.oCM_Register_Notification = &myCM_Register_Notification;
	cfgmgr32.oCM_Remove_SubTree = GetProcAddress(cfgmgr32.dll, "CM_Remove_SubTree");
	cfgmgr32.oCM_Remove_SubTree_Ex = GetProcAddress(cfgmgr32.dll, "CM_Remove_SubTree_Ex");
	cfgmgr32.oCM_Request_Device_EjectA = GetProcAddress(cfgmgr32.dll, "CM_Request_Device_EjectA");
	cfgmgr32.oCM_Request_Device_EjectW = GetProcAddress(cfgmgr32.dll, "CM_Request_Device_EjectW");
	cfgmgr32.oCM_Request_Device_Eject_ExA = GetProcAddress(cfgmgr32.dll, "CM_Request_Device_Eject_ExA");
	cfgmgr32.oCM_Request_Device_Eject_ExW = GetProcAddress(cfgmgr32.dll, "CM_Request_Device_Eject_ExW");
	cfgmgr32.oCM_Request_Eject_PC = GetProcAddress(cfgmgr32.dll, "CM_Request_Eject_PC");
	cfgmgr32.oCM_Request_Eject_PC_Ex = GetProcAddress(cfgmgr32.dll, "CM_Request_Eject_PC_Ex");
	cfgmgr32.oCM_RestoreAll_DefaultPowerSchemes = GetProcAddress(cfgmgr32.dll, "CM_RestoreAll_DefaultPowerSchemes");
	cfgmgr32.oCM_Restore_DefaultPowerScheme = GetProcAddress(cfgmgr32.dll, "CM_Restore_DefaultPowerScheme");
	cfgmgr32.oCM_Run_Detection = GetProcAddress(cfgmgr32.dll, "CM_Run_Detection");
	cfgmgr32.oCM_Run_Detection_Ex = GetProcAddress(cfgmgr32.dll, "CM_Run_Detection_Ex");
	cfgmgr32.oCM_Set_ActiveScheme = GetProcAddress(cfgmgr32.dll, "CM_Set_ActiveScheme");
	cfgmgr32.oCM_Set_Class_PropertyW = GetProcAddress(cfgmgr32.dll, "CM_Set_Class_PropertyW");
	cfgmgr32.oCM_Set_Class_Property_ExW = GetProcAddress(cfgmgr32.dll, "CM_Set_Class_Property_ExW");
	cfgmgr32.oCM_Set_Class_Registry_PropertyA = GetProcAddress(cfgmgr32.dll, "CM_Set_Class_Registry_PropertyA");
	cfgmgr32.oCM_Set_Class_Registry_PropertyW = GetProcAddress(cfgmgr32.dll, "CM_Set_Class_Registry_PropertyW");
	cfgmgr32.oCM_Set_DevNode_Problem = GetProcAddress(cfgmgr32.dll, "CM_Set_DevNode_Problem");
	cfgmgr32.oCM_Set_DevNode_Problem_Ex = GetProcAddress(cfgmgr32.dll, "CM_Set_DevNode_Problem_Ex");
	cfgmgr32.oCM_Set_DevNode_PropertyW = GetProcAddress(cfgmgr32.dll, "CM_Set_DevNode_PropertyW");
	cfgmgr32.oCM_Set_DevNode_Property_ExW = GetProcAddress(cfgmgr32.dll, "CM_Set_DevNode_Property_ExW");
	cfgmgr32.oCM_Set_DevNode_Registry_PropertyA = GetProcAddress(cfgmgr32.dll, "CM_Set_DevNode_Registry_PropertyA");
	cfgmgr32.oCM_Set_DevNode_Registry_PropertyW = GetProcAddress(cfgmgr32.dll, "CM_Set_DevNode_Registry_PropertyW");
	cfgmgr32.oCM_Set_DevNode_Registry_Property_ExA = GetProcAddress(cfgmgr32.dll, "CM_Set_DevNode_Registry_Property_ExA");
	cfgmgr32.oCM_Set_DevNode_Registry_Property_ExW = GetProcAddress(cfgmgr32.dll, "CM_Set_DevNode_Registry_Property_ExW");
	cfgmgr32.oCM_Set_Device_Interface_PropertyW = GetProcAddress(cfgmgr32.dll, "CM_Set_Device_Interface_PropertyW");
	cfgmgr32.oCM_Set_Device_Interface_Property_ExW = GetProcAddress(cfgmgr32.dll, "CM_Set_Device_Interface_Property_ExW");
	cfgmgr32.oCM_Set_HW_Prof = GetProcAddress(cfgmgr32.dll, "CM_Set_HW_Prof");
	cfgmgr32.oCM_Set_HW_Prof_Ex = GetProcAddress(cfgmgr32.dll, "CM_Set_HW_Prof_Ex");
	cfgmgr32.oCM_Set_HW_Prof_FlagsA = GetProcAddress(cfgmgr32.dll, "CM_Set_HW_Prof_FlagsA");
	cfgmgr32.oCM_Set_HW_Prof_FlagsW = GetProcAddress(cfgmgr32.dll, "CM_Set_HW_Prof_FlagsW");
	cfgmgr32.oCM_Set_HW_Prof_Flags_ExA = GetProcAddress(cfgmgr32.dll, "CM_Set_HW_Prof_Flags_ExA");
	cfgmgr32.oCM_Set_HW_Prof_Flags_ExW = GetProcAddress(cfgmgr32.dll, "CM_Set_HW_Prof_Flags_ExW");
	cfgmgr32.oCM_Setup_DevNode = GetProcAddress(cfgmgr32.dll, "CM_Setup_DevNode");
	cfgmgr32.oCM_Setup_DevNode_Ex = GetProcAddress(cfgmgr32.dll, "CM_Setup_DevNode_Ex");
	cfgmgr32.oCM_Test_Range_Available = GetProcAddress(cfgmgr32.dll, "CM_Test_Range_Available");
	cfgmgr32.oCM_Uninstall_DevNode = GetProcAddress(cfgmgr32.dll, "CM_Uninstall_DevNode");
	cfgmgr32.oCM_Uninstall_DevNode_Ex = GetProcAddress(cfgmgr32.dll, "CM_Uninstall_DevNode_Ex");
	cfgmgr32.oCM_Uninstall_DriverW = GetProcAddress(cfgmgr32.dll, "CM_Uninstall_DriverW");
	cfgmgr32.oCM_Unregister_Device_InterfaceA = GetProcAddress(cfgmgr32.dll, "CM_Unregister_Device_InterfaceA");
	cfgmgr32.oCM_Unregister_Device_InterfaceW = GetProcAddress(cfgmgr32.dll, "CM_Unregister_Device_InterfaceW");
	cfgmgr32.oCM_Unregister_Device_Interface_ExA = GetProcAddress(cfgmgr32.dll, "CM_Unregister_Device_Interface_ExA");
	cfgmgr32.oCM_Unregister_Device_Interface_ExW = GetProcAddress(cfgmgr32.dll, "CM_Unregister_Device_Interface_ExW");
	cfgmgr32.oCM_Unregister_Notification = GetProcAddress(cfgmgr32.dll, "CM_Unregister_Notification");
	cfgmgr32.oCM_Write_UserPowerKey = GetProcAddress(cfgmgr32.dll, "CM_Write_UserPowerKey");
	cfgmgr32.oDevCloseObjectQuery = GetProcAddress(cfgmgr32.dll, "DevCloseObjectQuery");
	cfgmgr32.oDevCreateObjectQuery = GetProcAddress(cfgmgr32.dll, "DevCreateObjectQuery");
	cfgmgr32.oDevCreateObjectQueryEx = GetProcAddress(cfgmgr32.dll, "DevCreateObjectQueryEx");
	cfgmgr32.oDevCreateObjectQueryFromId = GetProcAddress(cfgmgr32.dll, "DevCreateObjectQueryFromId");
	cfgmgr32.oDevCreateObjectQueryFromIdEx = GetProcAddress(cfgmgr32.dll, "DevCreateObjectQueryFromIdEx");
	cfgmgr32.oDevCreateObjectQueryFromIds = GetProcAddress(cfgmgr32.dll, "DevCreateObjectQueryFromIds");
	cfgmgr32.oDevCreateObjectQueryFromIdsEx = GetProcAddress(cfgmgr32.dll, "DevCreateObjectQueryFromIdsEx");
	cfgmgr32.oDevFindProperty = GetProcAddress(cfgmgr32.dll, "DevFindProperty");
	cfgmgr32.oDevFreeObjectProperties = GetProcAddress(cfgmgr32.dll, "DevFreeObjectProperties");
	cfgmgr32.oDevFreeObjects = GetProcAddress(cfgmgr32.dll, "DevFreeObjects");
	cfgmgr32.oDevGetObjectProperties = GetProcAddress(cfgmgr32.dll, "DevGetObjectProperties");
	cfgmgr32.oDevGetObjectPropertiesEx = GetProcAddress(cfgmgr32.dll, "DevGetObjectPropertiesEx");
	cfgmgr32.oDevGetObjects = GetProcAddress(cfgmgr32.dll, "DevGetObjects");
	cfgmgr32.oDevGetObjectsEx = GetProcAddress(cfgmgr32.dll, "DevGetObjectsEx");
	cfgmgr32.oDevSetObjectProperties = GetProcAddress(cfgmgr32.dll, "DevSetObjectProperties");
	cfgmgr32.oSwDeviceClose = GetProcAddress(cfgmgr32.dll, "SwDeviceClose");
	cfgmgr32.oSwDeviceCreate = GetProcAddress(cfgmgr32.dll, "SwDeviceCreate");
	cfgmgr32.oSwDeviceGetLifetime = GetProcAddress(cfgmgr32.dll, "SwDeviceGetLifetime");
	cfgmgr32.oSwDeviceInterfacePropertySet = GetProcAddress(cfgmgr32.dll, "SwDeviceInterfacePropertySet");
	cfgmgr32.oSwDeviceInterfaceRegister = GetProcAddress(cfgmgr32.dll, "SwDeviceInterfaceRegister");
	cfgmgr32.oSwDeviceInterfaceSetState = GetProcAddress(cfgmgr32.dll, "SwDeviceInterfaceSetState");
	cfgmgr32.oSwDevicePropertySet = GetProcAddress(cfgmgr32.dll, "SwDevicePropertySet");
	cfgmgr32.oSwDeviceSetLifetime = GetProcAddress(cfgmgr32.dll, "SwDeviceSetLifetime");
	cfgmgr32.oSwMemFree = GetProcAddress(cfgmgr32.dll, "SwMemFree");
}
#pragma endregion

//CONFIGRET myCM_Register_Notification(PCM_NOTIFY_FILTER pFilter, PVOID pContext, PCM_NOTIFY_CALLBACK pCallback, PHCMNOTIFICATION pNotifyContext) {
//	return CR_SUCCESS;
//}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		char path[MAX_PATH];
		GetWindowsDirectory(path, sizeof(path));

		// Example: "\\System32\\version.dll"
		strcat_s(path, "\\System32\\cfgmgr32.dll");
		cfgmgr32.dll = LoadLibrary(path);
		setupFunctions();

		// Add here your code, I recommend you to create a thread
		break;
	case DLL_PROCESS_DETACH:
		FreeLibrary(cfgmgr32.dll);
		break;
	}
	return 1;
}
