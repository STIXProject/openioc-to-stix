# Copyright (c) 2013, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

#OpenIOC -> CybOX Translator
#v0.21 BETA
#Creates CybOX 2.0.1 objects from IOC indicator item components 
import uuid
import cybox.bindings.cybox_core as core
import cybox.bindings.cybox_common as common

import cybox.bindings.account_object as accountobj
import cybox.bindings.address_object as addressobj
import cybox.bindings.disk_object as diskobj
import cybox.bindings.disk_partition_object as diskpartitionobj
import cybox.bindings.dns_record_object as dnsrecordobj
import cybox.bindings.email_message_object as emailmessageobj
import cybox.bindings.file_object as fileobj
import cybox.bindings.http_session_object as httpsessionobj
import cybox.bindings.library_object as libraryobj
import cybox.bindings.memory_object as memoryobj
import cybox.bindings.network_route_entry_object as networkreouteentryobj
import cybox.bindings.network_connection_object as networkconnectionobj
import cybox.bindings.port_object as portobj
import cybox.bindings.process_object as processobj
import cybox.bindings.socket_address_object as socketaddressobj
import cybox.bindings.system_object as systemobj
import cybox.bindings.unix_file_object as unixfileobj
import cybox.bindings.uri_object as uriobj
import cybox.bindings.user_account_object as useraccountobj
import cybox.bindings.volume_object as volumeobj
import cybox.bindings.win_driver_object as windriverobj
import cybox.bindings.win_event_log_object as wineventlogobj
import cybox.bindings.win_executable_file_object as winexecutablefileobj
import cybox.bindings.win_file_object as winfileobj
import cybox.bindings.win_handle_object as winhandleobj
import cybox.bindings.win_kernel_hook_object as winkernelhookobj
import cybox.bindings.win_memory_page_region_object as winmemorypageregionobj
import cybox.bindings.win_prefetch_object as winprefetchobj
import cybox.bindings.win_process_object as winprocessobj
import cybox.bindings.win_registry_key_object as winregistrykeyobj
import cybox.bindings.win_service_object as winserviceobj
import cybox.bindings.win_system_object as winsystemobj
import cybox.bindings.win_system_restore_object as winsystemrestoreobj
import cybox.bindings.win_task_object as wintaskobj
import cybox.bindings.win_user_account_object as winuseraccountobj
import cybox.bindings.win_volume_object as winvolumeobj

def createObj(search_string, content_string, condition):
    defined_object = None
    split_search_string = search_string.split('/',1)

    if split_search_string[0] == 'ArpEntryItem':
        # no relevant CybOX equivalent
        pass
    elif split_search_string[0] == 'CookieHistoryItem':
        # no relevant CybOX equivalent
        pass
    elif split_search_string[0] == 'DiskItem':
        defined_object = createDiskObj(search_string, content_string, condition)
    elif split_search_string[0] == 'DnsEntryItem':
        defined_object = createDNSObj(search_string, content_string, condition)
    elif split_search_string[0] == 'DriverItem':
        defined_object = createDriverObj(search_string, content_string, condition)
    elif split_search_string[0] == 'Email':
        defined_object = createEmailObj(search_string, content_string, condition)
    elif split_search_string[0] == 'EventLogItem':
        defined_object = createWinEventLogObj(search_string, content_string, condition)
    elif split_search_string[0] == 'FileDownloadHistoryItem':
        # no relevant CybOX equivalent
        pass
    elif split_search_string[0] == 'FileItem':
        defined_object = createFileObj(search_string, content_string, condition)
    elif split_search_string[0] == 'FormHistoryItem':
        # no relevant CybOX equivalent
        pass
    elif split_search_string[0] == 'HiveItem':
        # no relevant CybOX equivalent
        pass
    elif split_search_string[0] == 'HookItem':
        defined_object = createHookObj(search_string, content_string, condition)
    elif split_search_string[0] == 'ModuleItem':
        defined_object = createLibraryObj(search_string, content_string, condition)
    elif split_search_string[0] == 'Network':
        defined_object = createNetConnectionObj(search_string, content_string, condition)
    elif split_search_string[0] == 'PortItem':
        defined_object = createPortObj(search_string, content_string, condition)
    elif split_search_string[0] == 'PrefetchItem':
        defined_object = createPrefetchObj(search_string, content_string, condition)
    elif split_search_string[0] == 'ProcessItem':
        defined_object = createProcessObj(search_string, content_string, condition)
    elif split_search_string[0] == 'RegistryItem':
        defined_object = createRegObj(search_string, content_string, condition)
    elif split_search_string[0] == 'RouteEntryItem':
        defined_object = createNetRouteObj(search_string, content_string, condition)
    elif split_search_string[0] == 'ServiceItem':
        defined_object = createServiceObj(search_string, content_string, condition)
    elif split_search_string[0] == 'Snort':
        # no relevant CybOX equivalent
        pass
    elif split_search_string[0] == 'SystemInfoItem':
        defined_object = createSystemObj(search_string, content_string, condition)
    elif split_search_string[0] == 'SystemRestoreItem':
        defined_object = createSystemRestoreObj(search_string, content_string, condition)
    elif split_search_string[0] == 'TaskItem':
        defined_object = createWinTaskObject(search_string, content_string, condition)
    elif split_search_string[0] == 'UrlHistoryItem':
        # no relevant CybOX equivalent
        pass
    elif split_search_string[0] == 'UserItem':
        defined_object = createUserObj(search_string, content_string, condition)
    elif split_search_string[0] == 'VolumeItem':
        defined_object = createVolumeObj(search_string, content_string, condition)
    
    if defined_object: 
        if type(defined_object) is list:
            return defined_object

        if defined_object.hasContent_():
            defined_object.set_object_reference(None)
            return defined_object
        else:
            return None
    else:
        return None

## primary object functions

def createDiskObj(search_string, content_string, condition):
    #Create the disk object
    dskobj = diskobj.DiskObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "DiskItem/DiskName":
        dskobj.set_Disk_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "DiskItem/DiskSize":
        dskobj.set_Disk_Size(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "DiskItem/PartitionList/Partition/PartitionLength":
        partition_list = diskobj.PartitionListType()
        partition = diskpartitionobj.DiskPartitionObjectType()
        partition.set_Partition_Length(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
        partition_list.add_Partition(partition)
        dskobj.set_Partition_List(partition_list)
    elif search_string == "DiskItem/PartitionList/Partition/PartitionNumber":
        partition_list = diskobj.PartitionListType()
        partition = diskpartitionobj.DiskPartitionObjectType()
        partition.set_Partition_ID(process_numerical_value(common.IntegerObjectPropertyType(datatype=None), content_string, condition))
        partition_list.add_Partition(partition)
        dskobj.set_Partition_List(partition_list)
    elif search_string == "DiskItem/PartitionList/Partition/PartitionOffset":
        partition_list = diskobj.PartitionListType()
        partition = diskpartitionobj.DiskPartitionObjectType()
        partition.set_Partition_Offset(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
        partition_list.add_Partition(partition)
        dskobj.set_Partition_List(partition_list)
    elif search_string == "DiskItem/PartitionList/Partition/PartitionType":
        partition_list = diskobj.PartitionListType()
        partition = diskpartitionobj.DiskPartitionObjectType()
        partition.set_Type(common.StringObjectPropertyType(datatype='string', condition=condition, valueOf_=process_string_value(content_string)))
        partition_list.add_Partition(partition)
        dskobj.set_Partition_List(partition_list)

    if valueset:
        dskobj.set_xsi_type('DiskObj:DiskObjectType')
    elif not valueset:
        dskobj = None
    
    return dskobj

def createDNSObj(search_string, content_string, condition):
    #Create the dns cache object
    dnsobj = dnsrecordobj.DNSRecordObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "DnsEntryItem/DataLength":
        dnsobj.set_Data_Length(process_numerical_value(common.IntegerObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "DnsEntryItem/Flags":
        dnsobj.set_Flags(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "DnsEntryItem/Host":
        uri = uriobj.URIObjectType()
        uri.set_Value(common.AnyURIObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        dnsobj.set_Domain_Name(uri)
    elif search_string == "RecordData/Host": 
        dnsobj.set_Record_Data(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "RecordData/IPv4Address": 
        dnsobj.set_Record_Data(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "DnsEntryItem/RecordName":
        dnsobj.set_Record_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "DnsEntryItem/RecordType":
        dnsobj.set_Record_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "DnsEntryItem/TimeToLive":
        dnsobj.set_TTL(process_numerical_value(common.IntegerObjectPropertyType(datatype=None), content_string, condition))

    if valueset:
        dnsobj.set_xsi_type('DNSCacheObj:DNSCacheObjectType')
    elif not valueset:
        dnsobj = None

    return dnsobj

def createDriverObj(search_string, content_string, condition):
    #Create the driver object
    driverobj = windriverobj.WindowsDriverObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "DriverItem/CertificateIssuer":
        valueset = False
    elif search_string == "DriverItem/CertificateSubject":
        valueset = False
    elif search_string == "DriverItem/DeviceItem/AttachedDeviceName":
        device_list = windriverobj.DeviceObjectListType()
        device_objectstruct = windriverobj.DeviceObjectStructType()
        device_objectstruct.set_Attached_Device_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        device_list.add_Device_Object_Struct(device_objectstruct)
        driverobj.set_Device_Object_List(device_list)
    elif search_string == "DriverItem/DeviceItem/AttachedDeviceObject":
        device_list = windriverobj.DeviceObjectListType()
        device_objectstruct = windriverobj.DeviceObjectStructType()
        device_objectstruct.set_Attached_Device_Object(common.UnsignedLongObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        device_list.add_Device_Object_Struct(device_objectstruct)
        driverobj.set_Device_Object_List(device_list)
    elif search_string == "DriverItem/DeviceItem/AttachedDriverName":
        valueset = False
    elif search_string == "DriverItem/DeviceItem/AttachedDriverObject": 
        valueset = False
    elif search_string == "DriverItem/DeviceItem/AttachedToDeviceName":
        device_list = windriverobj.DeviceObjectListType()
        device_objectstruct = windriverobj.DeviceObjectStructType()
        device_objectstruct.set_Attached_To_Device_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        device_list.add_Device_Object_Struct(device_objectstruct)
        driverobj.set_Device_Object_List(device_list)
    elif search_string == "DriverItem/DeviceItem/AttachedToDeviceObject":
        device_list = windriverobj.DeviceObjectListType()
        device_objectstruct = windriverobj.DeviceObjectStructType()
        device_objectstruct.set_Attached_To_Device_Object(common.UnsignedLongObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        device_list.add_Device_Object_Struct(device_objectstruct)
        driverobj.set_Device_Object_List(device_list)
    elif search_string == "DriverItem/DeviceItem/AttachedToDriverName":
        device_list = windriverobj.DeviceObjectListType()
        device_objectstruct = windriverobj.DeviceObjectStructType()
        device_objectstruct.set_Attached_To_Driver_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        device_list.add_Device_Object_Struct(device_objectstruct)
        driverobj.set_Device_Object_List(device_list)
    elif search_string == "DriverItem/DeviceItem/AttachedToDriverObject":
        device_list = windriverobj.DeviceObjectListType()
        device_objectstruct = windriverobj.DeviceObjectStructType()
        device_objectstruct.get_Attached_To_Driver_Object(common.UnsignedLongObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        device_list.add_Device_Object_Struct(device_objectstruct)
        driverobj.set_Device_Object_List(device_list)
    elif search_string == "DriverItem/DeviceItem/DeviceName":
        device_list = windriverobj.DeviceObjectListType()
        device_objectstruct = windriverobj.DeviceObjectStructType()
        device_objectstruct.set_Device_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        device_list.add_Device_Object_Struct(device_objectstruct)
        driverobj.set_Device_Object_List(device_list)
    elif search_string == "DriverItem/DeviceItem/DeviceObject":
        device_list = windriverobj.DeviceObjectListType()
        device_objectstruct = windriverobj.DeviceObjectStructType()
        device_objectstruct.set_Device_Object(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
        device_list.add_Device_Object_Struct(device_objectstruct)
        driverobj.set_Device_Object_List(device_list)
    elif search_string == "DriverItem/DeviceItem/DriverName":
        device_list = windriverobj.DeviceObjectListType()
        device_objectstruct = windriverobj.DeviceObjectStructType()
        device_objectstruct.set_Driver_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        device_list.add_Device_Object_Struct(device_objectstruct)
        driverobj.set_Device_Object_List(device_list)
    elif search_string == "DriverItem/DriverInit":
        driverobj.set_Driver_Init(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "DriverItem/DriverName":
        driverobj.set_Driver_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "DriverItem/DriverObjectAddress":
        driverobj.set_Driver_Object_Address(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "DriverItem/DriverStartIo":
        driverobj.set_Driver_Start_IO(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "DriverItem/DriverUnload":
        driverobj.set_Driver_Unload(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "DriverItem/ImageBase":
        driverobj.set_Image_Base(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))  
    elif search_string == "DriverItem/ImageSize":
        driverobj.set_Image_Size(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))  
    elif search_string == "DriverItem/Md5sum":
        valueset = False
    elif search_string == "DriverItem/PEInfo/BaseAddress":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/DetectedAnomalies/string":
        valueset = False
    elif search_string == "DriverItem/PEInfo/DetectedEntryPointSignature/Name":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/DetectedEntryPointSignature/Type":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/DigitalSignature/CertificateIssuer":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/DigitalSignature/CertificateSubject":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/DigitalSignature/Description":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/DigitalSignature/SignatureExists":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/DigitalSignature/SignatureVerified":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/EpJumpCodes/Depth":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/EpJumpCodes/Opcodes":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/Exports/ExportedFunctions/string":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/Exports/ExportsTimeStamp":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/Exports/DllName":
        valueset = False
    elif search_string == "DriverItem/PEInfo/Exports/NumberOfFunctions":
        valueset = False
    elif search_string == "DriverItem/PEInfo/Exports/NumberOfNames":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/ExtraneousBytes":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/ImportedModules/Module/ImportedFunctions/string":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/ImportedModules/Module/Name":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/PEChecksum/PEComputedAPI":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/PEChecksum/PEFileAPI":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/PEChecksum/PEFileRaw":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/PETimeStamp":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/Sections/Section/DetectedCharacteristics":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/Sections/Section/DetectedSignatureKeys/string":
        valueset = False
    elif search_string == "DriverItem/PEInfo/Sections/Section/Entropy/CurveData/float":
        valueset = False
    elif search_string == "DriverItem/PEInfo/Sections/Section/Name":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/Sections/Section/SizeInBytes":
        valueset = False
    elif search_string == "DriverItem/PEInfo/Sections/Section/Type":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/Subsystem":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/PEInfo/Type":
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "DriverItem/Sha1sum":
        return createFileObj(search_string, content_string, condition)
    elif search_string == "DriverItem/Sha256sum":
        return createFileObj(search_string, content_string, condition)
    elif search_string == "DriverItem/SignatureDescription":
        valueset = False
    elif search_string == "DriverItem/SignatureExists":
        valueset = False
    elif search_string == "DriverItem/SignatureVerified":
        valueset = False
    elif search_string == "DriverItem/StringList/string":
        return createFileObj(search_string, content_string, condition)
    
    if valueset:
        driverobj.set_xsi_type('WinDriverObj:WindowsDriverObjectType')
    elif not valueset:
        driverobj = None
    
    return driverobj

def createEmailObj(search_string, content_string, condition):
    #Create the email object
    emailobj = emailmessageobj.EmailMessageObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True
    
    #Email attachments are a special case which must be referenced as RelatedObjects
    #setup list (emailobject + relatedobject) return value in case indicator is email attachment
    isAttachment = False
    retVal = []

    if search_string == "Email/Attachment/Content":
        valueset = False
    elif search_string == "Email/Attachment/MIMEType":
        valueset = False
    elif search_string == "Email/Attachment/Name":
        isAttachment = True
        email_attachments = emailmessageobj.AttachmentsType()
        attachment = emailmessageobj.AttachmentReferenceType()
        relobj = core.RelatedObjectType()
        fileattachobj = fileobj.FileObjectType()
        fileattachobj.set_xsi_type('FileObj:FileObjectType')
        fileattachobj.set_File_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        relobj.set_Properties(fileattachobj)
        relobj.set_id('cybox:related-object-' + str(uuid.uuid1())) 
        attachment.set_object_reference(relobj.get_id())
        email_attachments.add_File(attachment)
        emailobj.set_Attachments(email_attachments)
        retVal.append(emailobj)
        retVal.append(relobj)
    elif search_string == "Email/Attachment/SizeInBytes":
        isAttachment = True
        email_attachments = emailmessageobj.AttachmentsType()
        attachment = emailmessageobj.AttachmentReferenceType()
        relobj = core.RelatedObjectType()
        fileattachobj = fileobj.FileObjectType()
        fileattachobj.set_xsi_type('FileObj:FileObjectType')
        fileattachobj.set_Size_In_Bytes(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
        relobj.set_Properties(fileattachobj)
        relobj.set_Relationship(common.ControlledVocabularyStringType(valueOf_='Received', xsi_type='cyboxVocabs:ObjectRelationshipVocab-1.0')) 
        attachment.set_object_reference('FileObj')
        email_attachments.add_File(attachment)
        emailobj.set_Attachments(email_attachments)
        retVal.append(emailobj)
        retVal.append(relobj)
    elif search_string == "Email/AttachmentCount":
        valueset = False
    elif search_string == "Email/BCC":
        email_header = emailmessageobj.EmailHeaderType()
        email_bcc = emailmessageobj.EmailRecipientsType()
        email_recipient = addressobj.AddressObjectType()
        email_recipient.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        email_bcc.set_Recipient(email_recipient)
        email_header.set_BCC(email_bcc)
        emailobj.set_Header(email_header)
    elif search_string == "Email/Body":
        emailobj.set_Raw_Body(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "Email/CC":
        email_header = emailmessageobj.EmailHeaderType()
        email_cc = emailmessageobj.EmailRecipientsType()
        email_recipient = addressobj.AddressObjectType()
        email_recipient.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        email_cc.set_Recipient(email_recipient)
        email_header.set_CC(email_cc)
        emailobj.set_Header(email_header)
    elif search_string == "Email/Content-Type":
        email_header = emailmessageobj.EmailHeaderType()
        email_header.set_Content_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        emailobj.set_Header(email_header)
    elif search_string == "Email/Date":
        email_header = emailmessageobj.EmailHeaderType()
        email_header.set_Date(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        emailobj.set_Header(email_header)
    elif search_string == "Email/From":
        email_header = emailmessageobj.EmailHeaderType()
        email_from = addressobj.AddressObjectType()
        email_from.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        email_header.set_From(email_from)
        emailobj.set_Header(email_header)
    elif search_string == "Email/In-Reply-To":
        email_header = emailmessageobj.EmailHeaderType()
        email_header.set_In_Reply_To(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        emailobj.set_Header(email_header)
    elif search_string == "Email/MIME-Version":
        email_header = emailmessageobj.EmailHeaderType()
        email_header.set_MIME_Version(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        emailobj.set_Header(email_header)
    elif search_string == "Email/Received":
        email_header = emailmessageobj.EmailHeaderType()
        email_received = emailmessageobj.EmailReceivedLineType()
        email_received.set_Timestamp(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        email_header.set_Received_Lines(email_received)
        emailobj.set_Header(email_header)
    elif search_string == "Email/ReceivedFromHost":
        email_header = emailmessageobj.EmailHeaderType()
        email_received = emailmessageobj.EmailReceivedLineType()
        email_received.set_From(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        email_header.set_Received_Lines(email_received)
        emailobj.set_Header(email_header)
    elif search_string == "Email/ReceivedFromIP":
        email_header = emailmessageobj.EmailHeaderType()
        email_received = emailmessageobj.EmailReceivedLineType()
        email_received.set_From(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        email_header.set_Received_Lines(email_received)
        emailobj.set_Header(email_header)
    elif search_string == "Email/References":
        valueset = False
    elif search_string == "Email/Return-Path":
        valueset = False
    elif search_string == "Email/Subject":
        email_header = emailmessageobj.EmailHeaderType()
        email_header.set_Subject(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        emailobj.set_Header(email_header)
    elif search_string == "Email/Thread-Index":
        valueset = False
    elif search_string == "Email/Thread-Topic":
        valueset = False
    elif search_string == "Email/To":
        email_header = emailmessageobj.EmailHeaderType()
        email_recipients = emailmessageobj.EmailRecipientsType()
        email_to = addressobj.AddressObjectType()
        email_to.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        email_recipients.add_Recipient(email_to)
        email_header.set_To(email_recipients)
        emailobj.set_Header(email_header)
    elif search_string == "Email/X-MS-Has-Attach":
        valueset = False
    elif search_string == "Email/X-filenames":
        valueset = False
    elif search_string == "Email/X-filesizes":
        valueset = False
    elif search_string == "Email/X-filetypes":
        valueset = False

    if valueset:
        emailobj.set_xsi_type('EmailMessageObj:EmailMessageObjectType')
    elif not valueset:
        emailobj = None
    
    if isAttachment:
        return retVal
    
    return emailobj

def createWinEventLogObj(search_string, content_string, condition):
    #Create the Win event log object
    eventlogobj = wineventlogobj.WindowsEventLogObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True
    
    if search_string == "EventLogItem/CorrelationActivityId":
        eventlogobj.set_Correlation_Activity_ID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "EventLogItem/CorrelationRelatedActivityId":
        eventlogobj.set_Correlation_Related_Activity_ID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "EventLogItem/EID":
        eventlogobj.set_EID(common.LongObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "EventLogItem/ExecutionProcessId":
        eventlogobj.set_Execution_Process_ID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "EventLogItem/ExecutionThreadId":
        eventlogobj.set_Execution_Thread_ID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "EventLogItem/blob":
        eventlogobj.set_Blob(common.Base64BinaryObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "EventLogItem/category":
        eventlogobj.set_Category(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "EventLogItem/categoryNum":
        eventlogobj.set_Category_Num(common.LongObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "EventLogItem/genTime":
        eventlogobj.set_Generation_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "EventLogItem/index":
        eventlogobj.set_Index(common.LongObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "EventLogItem/log":
        eventlogobj.set_Log(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "EventLogItem/machine":
        eventlogobj.set_Machine(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "EventLogItem/message":
        eventlogobj.set_Message(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "EventLogItem/reserved":
        eventlogobj.set_Reserved(common.LongObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "EventLogItem/source":
        eventlogobj.set_Source(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "EventLogItem/type":
        eventlogobj.set_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "EventLogItem/unformattedMessage/string":
        unformatted_message_list = wineventlogobj.UnformattedMessageListType()
        unformatted_message_list.add_Unformatted_Message(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        eventlogobj.set_Unformatted_Message_List(unformatted_message_list)
    elif search_string == "EventLogItem/user":
        eventlogobj.set_User(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "EventLogItem/writeTime":
        eventlogobj.set_Write_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))

    if valueset:
        eventlogobj.set_xsi_type('WinEventLogObj:WindowsEventLogObjectType')
    elif not valueset:
        eventlogobj = None
    
    return eventlogobj

def createFileObj(search_string, content_string, condition):
    #Create the file object
    fleobj = fileobj.FileObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "FileItem/Accessed":
        fleobj.set_Accessed_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "FileItem/Changed":
        valueset = False
    elif search_string == "FileItem/Created":
        fleobj.set_Created_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "FileItem/DevicePath":
        fleobj.set_Device_Path(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "FileItem/Drive":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/FileAttributes":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/FileExtension":
        fleobj.set_File_Extension(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "FileItem/FileName":
        fleobj.set_File_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "FileItem/FilePath":
        fleobj.set_File_Path(fileobj.FilePathType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "FileItem/FilenameAccessed":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/FilenameChanged":
        valueset = False
    elif search_string == "FileItem/FilenameCreated":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/FilenameModified":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/FullPath":
        fleobj.set_Full_Path(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "FileItem/INode":
        return createUnixFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/Md5sum":
        hashes = common.HashListType()
        md5hash = common.HashType()
        md5hash.set_Type(common.ControlledVocabularyStringType(valueOf_='MD5', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        md5hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        hashes.add_Hash(md5hash)
        fleobj.set_Hashes(hashes)
    elif search_string == "FileItem/Modified":
        fleobj.set_Modified_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "FileItem/detectedAnomaly":
        valueset = False
    elif search_string.count('PEInfo') > 0:
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "FileItem/PeakCodeEntropy":
        valueset = False
    elif search_string == "FileItem/PeakEntropy":
        fleobj.set_Peak_Entropy(common.DoubleObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "FileItem/SecurityID":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/SecurityType":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/Sha1sum" or search_string == "DriverItem/Sha1sum":
        hashes = common.HashListType()
        sha1hash = common.HashType()
        sha1hash.set_Type(common.ControlledVocabularyStringType(valueOf_='SHA1', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        sha1hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        hashes.add_Hash(sha1hash)
        fleobj.set_Hashes(hashes)
    elif search_string == "FileItem/Sha256sum" or search_string == "DriverItem/Sha1sum":
        hashes = common.HashListType()
        sha256hash = common.HashType()
        sha256hash.set_Type(common.ControlledVocabularyStringType(valueOf_='SHA256', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        sha256hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        hashes.add_Hash(sha256hash)
        fleobj.set_Hashes(hashes)
    elif search_string == "FileItem/SizeInBytes":
        fleobj.set_Size_In_Bytes(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "FileItem/StreamList/Stream/Md5sum":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/StreamList/Stream/Name":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/StreamList/Stream/Sha1sum":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/StreamList/Stream/Sha256sum":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/StreamList/Stream/SizeInBytes":
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/StringList/string" or search_string == "DriverItem/StringList/string":
        extracted_features = common.ExtractedFeaturesType()
        strings = common.ExtractedStringsType()
        string  = common.ExtractedStringType()
        string.set_String_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        strings.add_String(string)
        extracted_features.set_Strings(strings)
        fleobj.set_Extracted_Features(extracted_features)       
    elif search_string == "FileItem/Username":
        fleobj.set_User_Owner(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        fleobj.set_xsi_type('FileObj:FileObjectType')
    elif not valueset:
        fleobj = None
    
    return fleobj

def createHookObj(search_string, content_string, condition):
    #Create the hook object
    hookobject = winkernelhookobj.WindowsKernelHookObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "HookItem/DigitalSignatureHooking/CertificateIssuer":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Certificate_Subject(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        hookobject.set_Digital_Signature_Hooking(digital_signature)
    elif search_string == "HookItem/DigitalSignatureHooking/CertificateSubject":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Certificate_Subject(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        hookobject.set_Digital_Signature_Hooking(digital_signature)
    elif search_string == "HookItem/DigitalSignatureHooking/Description":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Signature_Description(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        hookobject.set_Digital_Signature_Hooking(digital_signature)
    elif search_string == "HookItem/DigitalSignatureHooking/SignatureExists":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.signature_exists(content_string)
        hookobject.set_Digital_Signature_Hooking(digital_signature)
    elif search_string == "HookItem/DigitalSignatureHooking/SignatureVerified":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.signature_verified(content_string)
        hookobject.set_Digital_Signature_Hooking(digital_signature)
    elif search_string == "HookItem/DigitalSignatureHooked/CertificateIssuer":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Certificate_Subject(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        hookobject.set_Digital_Signature_Hooked(digital_signature)
    elif search_string == "HookItem/DigitalSignatureHooked/CertificateSubject":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Certificate_Subject(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        hookobject.set_Digital_Signature_Hooked(digital_signature)
    elif search_string == "HookItem/DigitalSignatureHooked/Description":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Signature_Description(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        hookobject.set_Digital_Signature_Hooked(digital_signature)
    elif search_string == "HookItem/DigitalSignatureHooked/SignatureExists":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.signature_exists(content_string)
        hookobject.set_Digital_Signature_Hooked(digital_signature)
    elif search_string == "HookItem/DigitalSignatureHooked/SignatureVerified":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.signature_verified(content_string)
        hookobject.set_Digital_Signature_Hooked(digital_signature)
    elif search_string == "HookItem/HookDescription":
        hookobject.set_Hook_Description(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "HookItem/HookedFunction":
        hookobject.set_Hooked_Function(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "HookItem/HookedModule":
        hookobject.set_Hooked_Module(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "HookItem/HookingAddress":
        hookobject.set_Hooking_Address(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "HookItem/HookingModule":
        hookobject.set_Hooking_Module(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        hookobject.set_xsi_type('WinKernelHookObj:WindowsKernelHookObjectType')
    elif not valueset:
        hookobject = None
    
    return hookobject

def createLibraryObj(search_string, content_string, condition):  
    #Create the library object
    libobj = libraryobj.LibraryObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "ModuleItem/ModuleAddress":
        valueset = False
    elif search_string == "ModuleItem/ModuleBase":
        libobj.set_Base_Address(common.HexBinaryObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ModuleItem/ModuleInit":
        valueset = False
    elif search_string == "ModuleItem/ModuleName":
        libobj.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ModuleItem/ModulePath":
        libobj.set_Path(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ModuleItem/ModuleSize":
        libobj.set_Size(common.UnsignedLongObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        libobj.set_xsi_type('LibraryObj:LibraryObjectType')
    elif not valueset:
        libobj = None

    return libobj

def createNetConnectionObj(search_string, content_string, condition):
    #Create the network connection object
    netconn = networkconnectionobj.NetworkConnectionObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "PortItem/localIP" or search_string == "ProcessItem/PortList/PortItem/localIP":
        socketaddr = socketaddressobj.SocketAddressObjectType()
        address = addressobj.AddressObjectType() 
        address.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        socketaddr.set_IP_Address(address)
        netconn.set_Source_Socket_Address(socketaddr)
    elif search_string == "PortItem/remoteIP" or search_string == "ProcessItem/PortList/PortItem/remoteIP":
        socketaddr = socketaddressobj.SocketAddressObjectType()
        address = addressobj.AddressObjectType() 
        address.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        socketaddr.set_IP_Address(address)
        netconn.set_Destination_Socket_Address(socketaddr)
    elif search_string == "Network/DNS" or search_string == "PortItem/remotePort":
        l7conn = networkconnectionobj.Layer7ConnectionsType()
        httpsession = httpsessionobj.HTTPSessionObjectType()
        httpreqrep = httpsessionobj.HTTPRequestResponseType()
        httpreq = httpsessionobj.HTTPClientRequestType()
        httphdr = httpsessionobj.HTTPRequestHeaderType()
        httphdrfields = httpsessionobj.HTTPRequestHeaderFieldsType()
        httphost = httpsessionobj.HostFieldType()
        hosturi = uriobj.URIObjectType()
        hosturi.set_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        httphost.set_Domain_Name(hosturi)
        httphdrfields.set_Host(httphost)
        httphdr.set_Parsed_Header(httphdrfields)
        httpreq.set_HTTP_Request_Header(httphdr)
        httpreqrep.set_HTTP_Client_Request(httpreq)
        httpsession.add_HTTP_Request_Response(httpreqrep)
        l7conn.set_HTTP_Session(httpsession)
        netconn.set_Layer7_Connections(l7conn)
    elif search_string == "Network/HTTP_Referr":
        l7conn = networkconnectionobj.Layer7ConnectionsType()
        httpsession = httpsessionobj.HTTPSessionObjectType()
        httpreqrep = httpsessionobj.HTTPRequestResponseType()
        httpreq = httpsessionobj.HTTPClientRequestType()
        httphdr = httpsessionobj.HTTPRequestHeaderType()
        httphdrfields = httpsessionobj.HTTPRequestHeaderFieldsType()
        refuri = uriobj.URIObjectType()
        refuri.set_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        httphdrfields.set_Referer(refuri)
        httphdr.set_Parsed_Header(httphdrfields)
        httpreq.set_HTTP_Request_Header(httphdr)
        httpreqrep.set_HTTP_Client_Request(httpreq)
        httpsession.add_HTTP_Request_Response(httpreqrep)
        l7conn.set_HTTP_Session(httpsession)
        netconn.set_Layer7_Connections(l7conn)
    elif search_string == "Network/String":
        l7conn = networkconnectionobj.Layer7ConnectionsType()
        httpsession = httpsessionobj.HTTPSessionObjectType()
        httpreqrep = httpsessionobj.HTTPRequestResponseType()
        httpreq = httpsessionobj.HTTPClientRequestType()
        httphdr = httpsessionobj.HTTPRequestHeaderType()
        httphdr.set_Raw_Header(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        httpreq.set_HTTP_Request_Header(httphdr)
        httpreqrep.set_HTTP_Client_Request(httpreq)
        httpsession.add_HTTP_Request_Response(httpreqrep)
        l7conn.set_HTTP_Session(httpsession)
        netconn.set_Layer7_Connections(l7conn)
    elif search_string == "Network/URI":
        l7conn = networkconnectionobj.Layer7ConnectionsType()
        httpsession = httpsessionobj.HTTPSessionObjectType()
        httpreqrep = httpsessionobj.HTTPRequestResponseType()
        httpreq = httpsessionobj.HTTPClientRequestType()
        reqline = httpsessionobj.HTTPRequestLineType()
        reqline.set_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        httpreq.set_HTTP_Request_Line(reqline)
        httpreqrep.set_HTTP_Client_Request(httpreq)
        httpsession.add_HTTP_Request_Response(httpreqrep)
        l7conn.set_HTTP_Session(httpsession)
        netconn.set_Layer7_Connections(l7conn)
    elif search_string == "Network/UserAgent":
        l7conn = networkconnectionobj.Layer7ConnectionsType()
        httpsession = httpsessionobj.HTTPSessionObjectType()
        httpreqrep = httpsessionobj.HTTPRequestResponseType()
        httpreq = httpsessionobj.HTTPClientRequestType()
        httphdr = httpsessionobj.HTTPRequestHeaderType()
        httphdrfields = httpsessionobj.HTTPRequestHeaderFieldsType()
        httphdrfields.set_User_Agent(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        httphdr.set_Parsed_Header(httphdrfields)
        httpreq.set_HTTP_Request_Header(httphdr)
        httpreqrep.set_HTTP_Client_Request(httpreq)
        httpsession.add_HTTP_Request_Response(httpreqrep)
        l7conn.set_HTTP_Session(httpsession)
        netconn.set_Layer7_Connections(l7conn)
    elif search_string == "PortItem/CreationTime" or search_string == "ProcessItem/PortList/PortItem/CreationTime":
        netconn.set_Creation_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        netconn.set_xsi_type('NetworkConnectionObj:NetworkConnectionObjectType')
    elif not valueset:
        netconn = None

    return netconn
    
def createNetRouteObj(search_string, content_string, condition):  
    #Create the network route entry object
    netrtobj = networkreouteentryobj.NetworkRouteEntryObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "RouteEntryItem/Destination":
        destination_address = addressobj.AddressObjectType(category='ipv4-addr')
        destination_address.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        netrtobj.set_Destination_Address(destination_address)
    elif search_string == "RouteEntryItem/Gateway":
        gateway_address = addressobj.AddressObjectType(category='ipv4-addr')
        gateway_address.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        netrtobj.set_Gateway_Address(gateway_address)
    elif search_string == "RouteEntryItem/Interface":
        netrtobj.set_Interface(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "RouteEntryItem/IsIPv6":
        netrtobj.set_is_ipv6(content_string)
    elif search_string == "RouteEntryItem/Metric":
        netrtobj.set_Metric(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "RouteEntryItem/Netmask":
        netmask = addressobj.AddressObjectType(category='ipv4-addr')
        netmask.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        netrtobj.set_Netmask(netmask)
    elif search_string == "RouteEntryItem/Protocol":
        netrtobj.set_Protocol(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "RouteEntryItem/RouteAge":
        netrtobj.set_Route_Age(common.DurationObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "RouteEntryItem/RouteType":
        netrtobj.set_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        
    if valueset:
        netrtobj.set_xsi_type('NetworkRouteEntryObj:NetworkRouteEntryObjectType')
    elif not valueset:
        netrtobj = None

    return netrtobj

def createPortObj(search_string, content_string, condition):
    #Create the port object
    portobject = portobj.PortObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "PortItem/CreationTime":
        return createNetConnectionObj(search_string, content_string, condition)
    elif search_string == "PortItem/localIP":
        return createNetConnectionObj(search_string, content_string, condition)
    elif search_string == "PortItem/localPort" or search_string == "PortItem/remotePort":
        portobject.set_Port_Value(process_numerical_value(common.PositiveIntegerObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "PortItem/path":
        valueset = False
    elif search_string == "PortItem/pid":
        valueset = False
    elif search_string == "PortItem/process":
        valueset = False
    elif search_string == "PortItem/protocol":
        protocol = portobj.Layer4ProtocolType()
        protocol.set_datatype('string')
        protocol.set_valueOf_(process_string_value(content_string))
        portobject.set_Layer4_Protocol(protocol)
    elif search_string == "PortItem/remoteIP":
        return createNetConnectionObj(search_string, content_string, condition)
    elif search_string == "PortItem/state":
        valueset = False

    if valueset:
        portobject.set_xsi_type('PortObj:PortObjectType')
    elif not valueset:
        portobject = None
    
    return portobject

def createPrefetchObj(search_string, content_string, condition):
    #Create the port object
    prefetchobject = winprefetchobj.WindowsPrefetchObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "PrefetchItem/AccessedFileList/AccessedFile":
        filelisttype = winprefetchobj.AccessedFileListType()
        filelisttype.add_Accessed_Filename(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        prefetchobject.set_Accessed_File_List(filelisttype)
    elif search_string == "PrefetchItem/ApplicationFileName":
        prefetchobject.set_Application_File_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "PrefetchItem/ApplicationFullPath":
        valueset = False
    elif search_string == "PrefetchItem/Created":
        valueset = False
    elif search_string == "PrefetchItem/FullPath":
        valueset = False
    elif search_string == "PrefetchItem/LastRun":
        prefetchobject.set_Last_Run(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "PrefetchItem/PrefetchHash":
        prefetchobject.set_Prefetch_Hash(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "PrefetchItem/VolumeList/VolumeItem/DevicePath":
        volume = winvolumeobj.WindowsVolumeObjectType()
        volume.set_Device_Path(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        prefetchobject.set_Volume(volume)
    elif search_string == "PrefetchItem/VolumeList/VolumeItem/CreationTime":
        volume = winvolumeobj.WindowsVolumeObjectType()
        volume.set_Creation_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        prefetchobject.set_Volume(volume)
    elif search_string == "PrefetchItem/VolumeList/VolumeItem/SerialNumber":
        volume = winvolumeobj.WindowsVolumeObjectType()
        volume.set_Serial_Number(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        prefetchobject.set_Volume(volume)
    elif search_string == "PrefetchItem/ReportedSizeInBytes":
        valueset = False
    elif search_string == "PrefetchItem/SizeInBytes":
        valueset = False
    elif search_string == "PrefetchItem/TimesExecuted":
        prefetchobject.set_Times_Executed(common.LongObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        prefetchobject.set_xsi_type('PortObj:PortObjectType')
    elif not valueset:
        prefetchobject = None
    
    return prefetchobject

def createProcessObj(search_string, content_string, condition):
    #Create the process object
    procobj = processobj.ProcessObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string.count("HandleList") > 0:
        return createWinProcessObj(search_string, content_string, condition)
    elif search_string == "ProcessItem/PortList/PortItem/CreationTime":
        return createNetConnectionObj(search_string, content_string, condition)
    elif search_string == "ProcessItem/PortList/PortItem/localIP":
        return createNetConnectionObj(search_string, content_string, condition)
    elif search_string == "ProcessItem/PortList/PortItem/localPort" or search_string == "ProcessItem/PortList/PortItem/remotePort":
        portlist = processobj.PortListType()
        port = portobj.PortObjectType()
        port.set_Port_Value(process_numerical_value(common.PositiveIntegerObjectPropertyType(datatype=None), content_string, condition))
        portlist.add_Port(port)
        procobj.set_Port_List(portlist)
    elif search_string == "ProcessItem/PortList/PortItem/path":
        valueset = False
    elif search_string == "ProcessItem/PortList/PortItem/pid":
        valueset = False
    elif search_string == "ProcessItem/PortList/PortItem/process":
        valueset = False
    elif search_string == "ProcessItem/PortList/PortItem/protocol":
        portlist = processobj.PortListType()
        port = portobj.PortObjectType()
        port.set_Layer4_Protocol(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        portlist.add_Port(port)
        procobj.set_Port_List(portlist)
    elif search_string == "ProcessItem/PortList/PortItem/remoteIP":
        return createNetConnectionObj(search_string, content_string, condition)
    elif search_string == "ProcessItem/PortList/PortItem/state":
        valueset = False
    elif search_string.count("SectionList") > 0:
        return createWinProcessObj(search_string, content_string, condition)
    elif search_string == "ProcessItem/SecurityID":
        return createWinProcessObj(search_string, content_string, condition)
    elif search_string == "ProcessItem/SecurityType":
        return createWinProcessObj(search_string, content_string, condition)
    elif search_string == "ProcessItem/StringList/string":
        extractedfeat = common.ExtractedFeaturesType()
        string_list = common.ExtractedStringsType()
        string = common.ExtractedStringType()
        string.set_String_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        string_list.add_String(string)
        extractedfeat.set_Strings(string_list)
        procobj.set_Extracted_Features(extractedfeat)
    elif search_string == "ProcessItem/Username":
        procobj.set_Username(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ProcessItem/arguments":
        image_info = processobj.ImageInfoType()
        image_info.set_Command_Line(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        procobj.set_Image_Info(image_info)
    elif search_string == "ProcessItem/detectedAnomaly":
        valueset = False
    elif search_string == "ProcessItem/hidden":
        procobj.set_is_hidden(content_string)
    elif search_string == "ProcessItem/kernelTime":
        valueset = False
    elif search_string == "ProcessItem/name":
        procobj.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ProcessItem/parentpid":
        procobj.set_Parent_PID(process_numerical_value(common.UnsignedIntegerObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "ProcessItem/path" or search_string == "ServiceItem/path":
        image_info = processobj.ImageInfoType()
        image_info.set_Path(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        procobj.set_Image_Info(image_info)
    elif search_string == "ProcessItem/pid":
        procobj.set_PID(process_numerical_value(common.UnsignedIntegerObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "ProcessItem/startTime":
        procobj.set_Start_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "ProcessItem/userTime":
        procobj.set_User_Time(common.DurationObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))

    if valueset:
        procobj.set_xsi_type('ProcessObj:ProcessObjectType')
    elif not valueset:
        procobj = None
    
    return procobj

def createRegObj(search_string, content_string, condition): 
    #Create the registry object
    regobj = winregistrykeyobj.WindowsRegistryKeyObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "RegistryItem/Hive":
        regobj.set_Hive(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "RegistryItem/KeyPath":
        regobj.set_Key(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "RegistryItem/Modified":
        regobj.set_Modified_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "RegistryItem/NumSubKeys":
        regobj.set_Number_Subkeys(process_numerical_value(common.UnsignedIntegerObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "RegistryItem/NumValues":
        regobj.set_Number_Values(process_numerical_value(common.UnsignedIntegerObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "RegistryItem/Path":
        split_path = content_string.split('\\', 1)
        if any("HKEY_" in s for s in split_path):
            regobj.set_Hive(common.StringObjectPropertyType(datatype=None, condition='Equals', valueOf_=split_path[0]))
            regobj.set_Key(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=split_path[1]))
        else:
            regobj.set_Key(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))        
    elif search_string == "RegistryItem/ReportedLengthInBytes":
        valueset = False
    elif search_string == "RegistryItem/Text" or search_string == "RegistryItem/Value":
        values = winregistrykeyobj.RegistryValuesType()
        value = winregistrykeyobj.RegistryValueType()
        value.set_Data(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        values.add_Value(value)
        regobj.set_Values(values)
    elif search_string == "RegistryItem/Type":
        values = winregistrykeyobj.RegistryValuesType()
        value = winregistrykeyobj.RegistryValueType()
        value.set_Datatype(common.StringObjectPropertyType(datatype='string', condition=condition, valueOf_=process_string_value(content_string)))
        values.add_Value(value)
        regobj.set_Values(values)
    elif search_string == "RegistryItem/Username":
        regobj.set_Creator_Username(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "RegistryItem/ValueName":
        values = winregistrykeyobj.RegistryValuesType()
        value = winregistrykeyobj.RegistryValueType()
        value.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        values.add_Value(value)
        regobj.set_Values(values)

    if valueset:
        regobj.set_xsi_type('WinRegistryKeyObj:WindowsRegistryKeyObjectType')
    elif not valueset:
        regobj = None
    
    return regobj

def createServiceObj(search_string, content_string, condition):
    #Create the service object
    serviceobj = winserviceobj.WindowsServiceObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "ServiceItem/arguments":
        serviceobj.set_Startup_Command_Line(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ServiceItem/description":
        description_list = winserviceobj.ServiceDescriptionListType()
        description_list.add_Description(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        serviceobj.set_Description_List(description_list)    
    elif search_string == "ServiceItem/descriptiveName":
        valueset = False
    elif search_string == "ServiceItem/mode":
        serviceobj.set_Startup_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ServiceItem/name":
        serviceobj.set_Service_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ServiceItem/path":
        return createProcessObj(search_string, content_string, condition)
    elif search_string == "ServiceItem/pathCertificateIssuer":
        valueset = False
    elif search_string == "ServiceItem/pathCertificateSubject":
        valueset = False
    elif search_string == "ServiceItem/pathSignatureDescription":
        valueset = False
    elif search_string == "ServiceItem/pathSignatureExists":
        valueset = False
    elif search_string == "ServiceItem/pathSignatureVerified":
        valueset = False
    elif search_string == "ServiceItem/pathmd5sum":
        valueset = False
    elif search_string == "ServiceItem/pathsha1sum":
        valueset = False
    elif search_string == "ServiceItem/pathsha256sum":
        valueset = False
    elif search_string == "ServiceItem/pid":
        return createProcessObj(search_string, content_string, condition)
    elif search_string == "ServiceItem/serviceDLL":
        serviceobj.set_Service_DLL(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ServiceItem/serviceDLLmd5sum":
        service_dll_hashes = common.HashListType()
        md5hash = common.HashType()
        md5hash.set_Type(common.ControlledVocabularyStringType(valueOf_='MD5', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        md5hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        service_dll_hashes.add_Hash(md5hash)
        serviceobj.set_Service_DLL_Hashes(service_dll_hashes)
    elif search_string == "ServiceItem/serviceDLLsha1sum":
        service_dll_hashes = common.HashListType()
        sha1hash = common.HashType()
        sha1hash.set_Type(common.ControlledVocabularyStringType(valueOf_='SHA1', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        sha1hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        service_dll_hashes.add_Hash(sha1hash)
        serviceobj.set_Service_DLL_Hashes(service_dll_hashes)
    elif search_string == "ServiceItem/serviceDLLsha256sum":
        service_dll_hashes = common.HashListType()
        sha256hash = common.HashType()
        sha256hash.set_Type(common.ControlledVocabularyStringType(valueOf_='SHA256', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        sha256hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        service_dll_hashes.add_Hash(sha256hash)
        serviceobj.set_Service_DLL_Hashes(service_dll_hashes)
    elif search_string == "ServiceItem/serviceDLLCertificateSubject":
        serviceobj.set_Service_DLL_Certificate_Subject(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ServiceItem/serviceDLLCertificateIssuer":
        serviceobj.set_Service_DLL_Certificate_Issuer(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ServiceItem/serviceDLLSignatureExists":
        serviceobj.set_service_dll_signature_exists(content_string)
    elif search_string == "ServiceItem/serviceDLLSignatureVerified":
        serviceobj.set_service_dll_signature_verified(content_string)
    elif search_string == "ServiceItem/serviceDLLSignatureDescription":
        serviceobj.set_Service_DLL_Signature_Description(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ServiceItem/startedAs":
        serviceobj.set_Started_As(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ServiceItem/status":
        serviceobj.set_Service_Status(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ServiceItem/type":
        serviceobj.set_Service_Type(common.StringObjectPropertyType(datatype='string', condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        serviceobj.set_xsi_type('WinServiceObj:WindowsServiceObjectType')
    elif not valueset:
        serviceobj = None

    return serviceobj

def createSystemObj(search_string, content_string, condition):
    #Create the system object
    sysobj = systemobj.SystemObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if content_string == 'SystemInfoItem/MAC' or content_string == 'SystemInfoItem/networkArray/networkInfo/MAC':
        network_interface_list = systemobj.NetworkInterfaceListType()
        network_interface = systemobj.NetworkInterfaceType()
        network_interface.set_MAC(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        network_interface_list.add_Network_Interface(network_interface)
        sysobj.set_Network_Interface_List(network_interface_list)
    elif content_string == 'SystemInfoItem/OS':
        os = systemobj.OSType()
        os.set_Platform(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        sysobj.set_OS(os)
    elif content_string == 'SystemInfoItem/availphysical':
        sysobj.set_Available_Physical_Memory(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
    elif content_string == 'SystemInfoItem/biosInfo/biosDate':
        bios_info = systemobj.BIOSInfoType()
        bios_info.set_BIOS_Date(common.DateObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        sysobj.set_BIOS_Info(bios_info)
    elif content_string == 'SystemInfoItem/biosInfo/biosVersion':
        bios_info = systemobj.BIOSInfoType()
        bios_info.set_BIOS_Version(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        sysobj.set_BIOS_Info(bios_info)
    elif content_string == 'SystemInfoItem/buildNumber':
        os = systemobj.OSType()
        os.set_Build_Number(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        sysobj.set_OS(os)
    elif content_string == 'SystemInfoItem/date':
        sysobj.set_Date(common.DateObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif content_string == 'SystemInfoItem/directory':
        valueset = False
    elif content_string == 'SystemInfoItem/domain':
        createWinSystemObj(search_string, content_string, condition)
    elif content_string == 'SystemInfoItem/hostname':
        sysobj.set_Hostname(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == 'SystemInfoItem/installDate':
        os = systemobj.OSType()
        os.set_Install_Date(common.DateObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        sysobj.set_OS(os)
    elif content_string == 'SystemInfoItem/machine':
        valueset = False
    elif content_string == 'SystemInfoItem/networkArray/networkInfo/MAC':
        network_interface_list = systemobj.NetworkInterfaceListType()
        network_interface = systemobj.NetworkInterfaceType()
        network_interface.set_MAC(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        network_interface_list.add_Network_Interface(network_interface)
        sysobj.set_Network_Interface_List(network_interface_list)
    elif content_string == 'SystemInfoItem/networkArray/networkInfo/adapter':
        network_interface_list = systemobj.NetworkInterfaceListType()
        network_interface = systemobj.NetworkInterfaceType()
        network_interface.set_Adapter(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        network_interface_list.add_Network_Interface(network_interface)
        sysobj.set_Network_Interface_List(network_interface_list)
    elif content_string == 'SystemInfoItem/networkArray/networkInfo/description':
        network_interface_list = systemobj.NetworkInterfaceListType()
        network_interface = systemobj.NetworkInterfaceType()
        network_interface.set_Description(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        network_interface_list.add_Network_Interface(network_interface)
        sysobj.set_Network_Interface_List(network_interface_list)
    elif content_string == 'SystemInfoItem/networkArray/networkInfo/dhcpLeaseExpires':
        network_interface_list = systemobj.NetworkInterfaceListType()
        network_interface = systemobj.NetworkInterfaceType()
        network_interface.set_DHCP_Lease_Expires(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        network_interface_list.add_Network_Interface(network_interface)
        sysobj.set_Network_Interface_List(network_interface_list)
    elif content_string == 'SystemInfoItem/networkArray/networkInfo/dhcpLeaseObtained':
        network_interface_list = systemobj.NetworkInterfaceListType()
        network_interface = systemobj.NetworkInterfaceType()
        network_interface.set_DHCP_Lease_Obtained(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        network_interface_list.add_Network_Interface(network_interface)
        sysobj.set_Network_Interface_List(network_interface_list)
    elif content_string == 'SystemInfoItem/networkArray/networkInfo/dhcpServerArray/dhcpServer':
        network_interface_list = systemobj.NetworkInterfaceListType()
        network_interface = systemobj.NetworkInterfaceType()
        dhcp_server_list = systemobj.DHCPServerListType()
        dhcp_server_address = addressobj.AddressObjectType(category='ipv4-addr')
        dhcp_server_address.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        dhcp_server_list.add_DHCP_Server_Address(dhcp_server_address)
        network_interface.set_DHCP_Server_List(dhcp_server_list)
        network_interface_list.add_Network_Interface(network_interface)
        sysobj.set_Network_Interface_List(network_interface_list)
    elif search_string == 'SystemInfoItem/networkArray/networkInfo/ipArray/ipInfo/ipAddress':
        network_interface_list = systemobj.NetworkInterfaceListType()
        network_interface = systemobj.NetworkInterfaceType()
        ip_list = systemobj.IPInfoListType()
        ip_info = systemobj.IPInfoType()
        ip_address = addressobj.AddressObjectType(category='ipv4-addr')
        ip_address.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        ip_info.set_IP_Address(ip_address)
        ip_list.add_IP_Info(ip_info)
        network_interface.set_IP_List(ip_list)
        network_interface_list.add_Network_Interface(network_interface)
        sysobj.set_Network_Interface_List(network_interface_list)
    elif content_string == 'SystemInfoItem/networkArray/networkInfo/ipArray/ipInfo/subnetMask':
        network_interface_list = systemobj.NetworkInterfaceListType()
        network_interface = systemobj.NetworkInterfaceType()
        ip_list = systemobj.IPInfoListType()
        ip_info = systemobj.IPInfoType()
        subnet_mask = addressobj.AddressObjectType(category='ipv4-addr')
        subnet_mask.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        ip_info.set_Subnet_Mask(subnet_mask)
        ip_list.add_IP_Info(ip_info)
        network_interface.set_IP_List(ip_list)
        network_interface_list.add_Network_Interface(network_interface)
        sysobj.set_Network_Interface_List(network_interface_list)
    elif content_string == 'SystemInfoItem/networkArray/networkInfo/ipGatewayArray/ipGateway':
        valueset = False
    elif content_string == 'SystemInfoItem/patchLevel':
        os = systemobj.OSType()
        os.set_Patch_Level(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        sysobj.set_OS(os)
    elif content_string == 'SystemInfoItem/procType':
        sysobj.set_Processor_Architecture(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == 'SystemInfoItem/processor':
        sysobj.set_Processor(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == 'SystemInfoItem/productID':
        return createWinSystemObj(search_string, content_string, condition)
    elif content_string == 'SystemInfoItem/productName':
        return createWinSystemObj(search_string, content_string, condition)
    elif content_string == 'SystemInfoItem/regOrg':
        return createWinSystemObj(search_string, content_string, condition)
    elif content_string == 'SystemInfoItem/regOwner':
        return createWinSystemObj(search_string, content_string, condition)
    elif content_string == 'SystemInfoItem/timezoneDST':
        sysobj.set_Timezone_DST(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == 'SystemInfoItem/timezoneStandard':
        sysobj.set_Timezone_Standard(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == 'SystemInfoItem/totalphysical':
        sysobj.set_Total_Physical_Memory(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
    elif content_string == 'SystemInfoItem/uptime':
        sysobj.set_Total_Physical_Memory(common.DurationObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif content_string == 'SystemInfoItem/user':
        sysobj.set_Total_Physical_Memory(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        sysobj.set_xsi_type('SystemObj:SystemObjectType')
    elif not valueset:
        sysobj = None

    return sysobj

def createSystemRestoreObj(search_string, content_string, condition):
    #Create the restore object
    restoreobject = winsystemrestoreobj.WindowsSystemRestoreObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if content_string == "SystemRestoreItem/RestorePointName":
        restoreobject.set_Restore_Point_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/RestorePointFullPath":
        restoreobject.set_Restore_Point_Full_Path(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/RestorePointDescription":
        restoreobject.set_Restore_Point_Description(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/RestorePointType":
        restoreobject.set_Restore_Point_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/Created":
        restoreobject.set_Created(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/RegistryHives/String":
        registryhivelist = winsystemrestoreobj.HiveListType()
        registryhivelist.add_Hive(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        restoreobject.set_Registry_Hive_List(registryhivelist)
    elif content_string == "SystemRestoreItem/ChangeLogFileName":
        restoreobject.set_Change_Log_File_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/ChangeLogEntrySequenceNumber":
        restoreobject.set_Change_Log_File_Name(common.LongObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/ChangeLogEntryType":
        logentrytype = winsystemrestoreobj.ChangeLogEntryTypeType()
        logentrytype.set_datatype(common.StringObjectPropertyType(datatype='string', condition=condition, valueOf_=process_string_value(content_string)))
        restoreobject.set_ChangeLog_Entry_Type(logentrytype)
    elif content_string == "SystemRestoreItem/ChangeLogEntryFlags":
        restoreobject.set_ChangeLog_Entry_Flags(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/FileAttributes":
        restoreobject.set_File_Attributes(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/OriginalFileName":
        restoreobject.Original_File_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/BackupFileName":
        restoreobject.Backup_File_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/AclChangeUsername":
        restoreobject.ACL_Change_Username(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/AclChangeSecurityID":
        restoreobject.ACL_Change_SID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif content_string == "SystemRestoreItem/OriginalShortFileName":
        restoreobject.Original_Short_File_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        restoreobject.set_xsi_type('WinSystemRestoreObj:WindowsSystemRestoreObjectType')
    elif not valueset:
        restoreobject = None
            
    return restoreobject

def createUserObj(search_string, content_string, condition):
    #Create the user account object
    accountobj = useraccountobj.UserAccountObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True
        
    if search_string == "UserItem/SecurityID":
        return createWinUserObj(search_string, content_string, condition)
    elif search_string == "UserItem/SecurityType":
        return createWinUserObj(search_string, content_string, condition)
    elif search_string == "UserItem/Username":
        accountobj.set_Username(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "UserItem/description":
        return createAccountObj(search_string, content_string, condition)
    elif search_string == "UserItem/disabled":
        return createAccountObj(search_string, content_string, condition)
    elif search_string == "UserItem/fullname":
        accountobj.set_Full_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "UserItem/grouplist/groupname":
        group_list = useraccountobj.GroupListType()
        group = winuseraccountobj.WindowsGroupType()
        group.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        group_list.add_Group(group)
        accountobj.set_Group_List(group_list)
    elif search_string == "UserItem/homedirectory":
        accountobj.set_Home_Directory(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "UserItem/lockedout":
        return createAccountObj(search_string, content_string, condition)
    elif search_string == "UserItem/passwordrequired":
        accountobj.set_password_required(content_string)
    elif search_string == "UserItem/scriptpath":
        accountobj.set_Script_path(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "UserItem/userpasswordage":
        accountobj.set_User_Password_Age(common.DurationObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))

    if valueset:
        accountobj.set_xsi_type('UserAccountObj:UserAccountObjectType')
    elif not valueset:
        accountobj = None
            
    return accountobj

def createVolumeObj(search_string, content_string, condition):
    #Create the volume object
    volobj = volumeobj.VolumeObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "VolumeItem/ActualAvailableAllocationUnits":
        volobj.set_Actual_Available_Allocation_Units(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "VolumeItem/BytesPerSector":
        volobj.set_Bytes_Per_Sector(process_numerical_value(common.PositiveIntegerObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "VolumeItem/CreationTime":
        volobj.set_Creation_Time(common.DateObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "VolumeItem/DevicePath":
        volobj.set_Device_Path(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "VolumeItem/DriveLetter":
        return createWinVolumeObj(search_string, content_string, condition)
    elif search_string == "VolumeItem/FileSystemFlags":
        file_system_flag_list = volumeobj.FileSystemFlagListType()
        file_system_flag = volumeobj.VolumeFileSystemFlagType(datatype=None, condition=condition, valueOf_=content_string)
        file_system_flag_list.add_File_System_Flag(file_system_flag)
        volobj.set_File_System_Flag_List(file_system_flag_list)
    elif search_string == "VolumeItem/FileSystemType":
        volobj.set_File_System_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "VolumeItem/IsMounted":
        volobj.set_ismounted(content_string)
    elif search_string == "VolumeItem/Name":
        volobj.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "VolumeItem/SectorsPerAllocationUnit":
        volobj.set_Sectors_Per_Allocation_Unit(process_numerical_value(common.UnsignedIntegerObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "VolumeItem/SerialNumber":
        volobj.set_Serial_Number(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "VolumeItem/TotalAllocationUnits":
        volobj.set_Total_Allocation_Units(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "VolumeItem/TotalAllocationUnits":
        volobj.set_Total_Allocation_Units(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "VolumeItem/Type":
        valueset = False
    elif search_string == "VolumeItem/VolumeName":
        valueset = False

    if valueset:
        volobj.set_xsi_type('VolumeObj:VolumeObjectType')
    elif not valueset:
        volobj = None

    return volobj
    
## specialized object functions

def createWinSystemObj(search_string, content_string, condition):
    #Create the Windows system object
    winsysobj = winsystemobj.WindowsSystemObjectType()
    
    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True
    
    if search_string == 'SystemInfoItem/domain':
        stringobjattribute = common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string))
        winsysobj.set_Domain(stringobjattribute)
    elif search_string == 'SystemInfoItem/productID':
        stringobjattribute = common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string))
        winsysobj.set_Product_ID(stringobjattribute)
    elif search_string == 'SystemInfoItem/productName':
        stringobjattribute = common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string))
        winsysobj.set_Product_Name(stringobjattribute)
    elif search_string == 'SystemInfoItem/regOrg':
        stringobjattribute = common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string))
        winsysobj.set_Registered_Organization(stringobjattribute)
    elif search_string == 'SystemInfoItem/regOwner':
        stringobjattribute = common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string))
        winsysobj.set_Registered_Owner(stringobjattribute)
    
    if valueset:
        winsysobj.set_xsi_type('WinSystemObj:WindowsSystemObjectType')
    elif not valueset:
        winsysobj = None

    return winsysobj

def createWinTaskObject(search_string, content_string, condition):
    #Create the user account object
    taskobj = wintaskobj.WindowsTaskObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "TaskItem/AccountLogonType":
        taskobj.set_Account_Logon_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/AccountName":
        taskobj.set_Account_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/AccountRunLevel":
        taskobj.set_Account_Run_Level(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/ActionList/Action/ActionType":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        actiontype = wintaskobj.TaskActionTypeType()
        actiontype.set_valueOf_(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        action.set_Action_Type(actiontype)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/COMClassId":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        icomhandler = wintaskobj.IComHandlerActionType()
        icomhandler.set_COM_Class_ID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        action.set_IComHandlerAction(icomhandler)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/COMData":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        icomhandler = wintaskobj.IComHandlerActionType()
        icomhandler.set_COM_Data(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        action.set_IComHandlerAction(icomhandler)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string.count("DigitalSignature") > 0: 
        valueset = False
    elif search_string == "TaskItem/ActionList/Action/EmailAttachments":
        #unlike the Email indicator, this TaskItem does not break EmailAttachments into component parts
        valueset = False
    elif search_string == "TaskItem/ActionList/Action/EmailBCC":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        emailmsg = createEmailObj("Email/BCC", content_string, condition)
        action.set_IEmailAction(emailmsg)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/EmailBody":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        emailmsg = createEmailObj("Email/Body", content_string, condition)
        action.set_IEmailAction(emailmsg)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/EmailCC":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        emailmsg = createEmailObj("Email/CC", content_string, condition)
        action.set_IEmailAction(emailmsg)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/EmailFrom":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        emailmsg = createEmailObj("Email/From", content_string, condition)
        action.set_IEmailAction(emailmsg)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/EmailReplyTo":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        #no base email reply-to indicator
        emailobj = emailmessageobj.EmailMessageObjectType()
        email_header = emailmessageobj.EmailHeaderType()
        email_replyto = addressobj.AddressObjectType()
        email_replyto.set_Address_Value(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        email_header.set_Reply_To(email_replyto)
        emailobj.set_Header(email_header)
        action.set_IEmailAction(emailobj)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/EmailServer":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        #no base email server indicator
        emailobj = emailmessageobj.EmailMessageObjectType()
        emailobj.set_Email_Server(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        action.set_IEmailAction(emailobj)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/EmailSubject":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        emailmsg = createEmailObj("Email/Subject", content_string, condition)
        action.set_IEmailAction(emailmsg)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/EmailTo":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        emailmsg = createEmailObj("Email/To", content_string, condition)
        action.set_IEmailAction(emailmsg)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/ExecArguments":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        execactiontype = wintaskobj.IExecActionType()
        execactiontype.set_Exec_Arguments(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        action.set_IExecAction(execactiontype)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/ExecProgramMd5sum":
        valueset = False
    elif search_string == "TaskItem/ActionList/Action/ExecProgramPath":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        execactiontype = wintaskobj.IExecActionType()
        execactiontype.set_Exec_Program_Path(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        action.set_IExecAction(execactiontype)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/ExecProgramSha1sum":
        valueset = False
    elif search_string == "TaskItem/ActionList/Action/ExecProgramSha256sum":
        valueset = False
    elif search_string == "TaskItem/ActionList/Action/ExecWorkingDirectory":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        execactiontype = wintaskobj.IExecActionType()
        execactiontype.set_Exec_Working_Directory(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        action.set_IExecAction(execactiontype)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/ShowMessageBody":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        showmsgaction = wintaskobj.IShowMessageActionType()
        showmsgaction.set_Show_Message_Body(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        action.set_IExecAction(showmsgaction)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ActionList/Action/ShowMessageTitle":
        actionlist = wintaskobj.TaskActionListType()
        action = wintaskobj.TaskActionType()
        showmsgaction = wintaskobj.IShowMessageActionType()
        showmsgaction.set_Show_Message_Title(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        action.set_IExecAction(showmsgaction)
        actionlist.add_Action(action)
        taskobj.set_Action_List(actionlist)
    elif search_string == "TaskItem/ApplicationName":
        taskobj.set_Application_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/CertificateIssuer":
        valueset = False
    elif search_string == "TaskItem/CertificateSubject":
        valueset = False
    elif search_string == "TaskItem/Comment":
        taskobj.set_Comment(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/CreationDate":
        taskobj.set_Creation_Date(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/Creator":
        taskobj.set_Creator(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/ExitCode":
        taskobj.set_Exit_Code(common.LongObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/Flag":
        flags = wintaskobj.TaskFlagType()
        flags.set_valueOf_(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        taskobj.set_Flags(flags)
    elif search_string == "TaskItem/MaxRunTime":
        taskobj.set_Max_Run_Time(common.UnsignedLongObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/MostRecentRunTime":
        taskobj.set_Most_Recent_Run_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/Name":
        taskobj.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/NextRunTime":
        taskobj.set_Next_Run_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/Parameters":
        taskobj.set_Parameters(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/Priority":
        priority = wintaskobj.TaskPriorityType()
        priority.set_valueOf_(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        taskobj.set_Priority(priority)
    elif search_string == "TaskItem/SignatureDescription":
        valueset = False
    elif search_string == "TaskItem/SignatureExists":
        valueset = False
    elif search_string == "TaskItem/SignatureVerified":
        valueset = False
    elif search_string == "TaskItem/Status":
        status = wintaskobj.TaskStatusType()
        status.set_valueOf_(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        taskobj.set_Status(status)
    elif search_string == "TaskItem/TriggerList/Trigger/TriggerBegin":
        triggerlist = wintaskobj.TriggerListType()
        trigger = wintaskobj.TriggerType()
        trigger.set_Trigger_Begin(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        triggerlist.add_Trigger(trigger)
        taskobj.set_Trigger_List(triggerlist)
    elif search_string == "TaskItem/TriggerList/Trigger/TriggerDelay":
        triggerlist = wintaskobj.TriggerListType()
        trigger = wintaskobj.TriggerType()
        trigger.set_Trigger_Delay(common.DurationObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        triggerlist.add_Trigger(trigger)
        taskobj.set_Trigger_List(triggerlist)
    elif search_string == "TaskItem/TriggerList/Trigger/TriggerEnabled":
        valueset = False
    elif search_string == "TaskItem/TriggerList/Trigger/TriggerEnd":
        triggerlist = wintaskobj.TriggerListType()
        trigger = wintaskobj.TriggerType()
        trigger.set_Trigger_End(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        triggerlist.add_Trigger(trigger)
        taskobj.set_Trigger_List(triggerlist)
    elif search_string == "TaskItem/TriggerList/Trigger/TriggerFrequency":
        triggerlist = wintaskobj.TriggerListType()
        trigger = wintaskobj.TriggerType()
        triggerfreq = wintaskobj.TaskTriggerFrequencyType()
        triggerfreq.set_valueOf_(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        trigger.set_Trigger_Frequency(triggerfreq)
        triggerlist.add_Trigger(trigger)
        taskobj.set_Trigger_List(triggerlist)
    elif search_string == "TaskItem/TriggerList/Trigger/TriggerMaxRunTime":
        triggerlist = wintaskobj.TriggerListType()
        trigger = wintaskobj.TriggerType()
        trigger.set_Trigger_Max_Run_Time(common.DurationObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        triggerlist.add_Trigger(trigger)
        taskobj.set_Trigger_List(triggerlist)
    elif search_string == "TaskItem/TriggerList/Trigger/TriggerSessionChangeType":
        triggerlist = wintaskobj.TriggerListType()
        trigger = wintaskobj.TriggerType()
        trigger.set_Trigger_Session_Change_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        triggerlist.add_Trigger(trigger)
        taskobj.set_Trigger_List(triggerlist)
    elif search_string == "TaskItem/TriggerList/Trigger/TriggerSubscription":
        valueset = False
    elif search_string == "TaskItem/TriggerList/Trigger/TriggerUsername":
        valueset = False
    elif search_string == "TaskItem/TriggerList/Trigger/TriggerValueQueries":
        valueset = False
    elif search_string == "TaskItem/VirtualPath":
        valueset = False
    elif search_string == "TaskItem/WorkItemData":
        taskobj.set_Work_Item_Data(common.Base64BinaryObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/WorkingDirectory":
        taskobj.set_Working_Directory(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "TaskItem/md5sum":
        valueset = False
    elif search_string == "TaskItem/sha1sum":
        valueset = False
    elif search_string == "TaskItem/sha256sum":
        valueset = False

    if valueset:
        taskobj.set_xsi_type('WinTaskObj:WindowsTaskObjectType')
    elif not valueset:
        taskobj = None
            
    return taskobj
   
def createWinVolumeObj(search_string, content_string, condition):
    #Create the volume object
    winvolobj = winvolumeobj.WindowsVolumeObjectType()
    
    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True
    
    if search_string == "VolumeItem/DriveLetter":
        winvolobj.set_Drive_Letter(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        winvolobj.set_xsi_type('WinVolumeObj:WindowsVolumeObjectType')
    elif not valueset:
        winvolobj = None

    return winvolobj 

def createUnixFileObj(search_string, content_string, condition):
    #Create the unix file object
    fileobj = unixfileobj.UnixFileObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "FileItem/INode":
        fileobj.set_INode(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))

    if valueset:
        fileobj.set_xsi_type('UnixFileObj:UnixFileObjectType')
    elif not valueset:
        fileobj = None
    
    return fileobj
    
def createWinFileObj(search_string, content_string, condition):
    #Create the windows file object
    fileobj = winfileobj.WindowsFileObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True
        
    if search_string == "FileItem/Drive": 
        fileobj.set_Drive(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "FileItem/FileAttributes":
        fileattlist = winfileobj.WindowsFileAttributesType()
        fileatt = winfileobj.WindowsFileAttributeType()
        fileatt.set_valueOf_(process_string_value(content_string))
        fileattlist.add_Attribute(fileatt)
        fileobj.set_File_Attributes_List(fileattlist)
    elif search_string == "FileItem/FilenameAccessed": 
        fileobj.set_Filename_Accessed_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "FileItem/FilenameCreated": 
        fileobj.set_Filename_Created_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "FileItem/FilenameModified": 
        fileobj.set_Filename_Modified_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "FileItem/SecurityID":
        fileobj.set_Security_ID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "FileItem/SecurityType":
        fileobj.set_Security_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "FileItem/StreamList/Stream/Md5sum":
        stream_list = winfileobj.StreamListType()
        stream = winfileobj.StreamObjectType()
        md5hash = common.HashType()
        md5hash.set_Type(common.ControlledVocabularyStringType(valueOf_='MD5', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        md5hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        stream.add_Hash(md5hash)
        stream_list.add_Stream(stream)
        fileobj.set_Stream_List(stream_list)
    elif search_string == "FileItem/StreamList/Stream/Name":
        stream_list = winfileobj.StreamListType()
        stream = winfileobj.StreamObjectType()
        stream.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        stream_list.add_Stream(stream)
        fileobj.set_Stream_List(stream_list)
    elif search_string == "FileItem/StreamList/Stream/Sha1sum":
        stream_list = winfileobj.StreamListType()
        stream = winfileobj.StreamObjectType()
        sha1hash = common.HashType()
        sha1hash.set_Type(common.ControlledVocabularyStringType(valueOf_='SHA1', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        sha1hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        stream.add_Hash(sha1hash)
        stream_list.add_Stream(stream)
        fileobj.set_Stream_List(stream_list)
    elif search_string == "FileItem/StreamList/Stream/Sha256sum":
        stream_list = winfileobj.StreamListType()
        stream = winfileobj.StreamObjectType()
        sha256hash = common.HashType()
        sha256hash.set_Type(common.ControlledVocabularyStringType(valueOf_='SHA256', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        sha256hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        stream.add_Hash(sha256hash)
        stream_list.add_Stream(stream)
        fileobj.set_Stream_List(stream_list)
    elif search_string == "FileItem/StreamList/Stream/SizeInBytes":
        stream_list = winfileobj.StreamListType()
        stream = winfileobj.StreamObjectType()
        stream.set_Size_In_Bytes(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
        stream_list.add_Stream(stream)
        fileobj.set_Stream_List(stream_list)

    if valueset:
        fileobj.set_xsi_type('WinFileObj:WindowsFileObjectType')
    elif not valueset:
        fileobj = None
    
    return fileobj

def createWinExecObj(search_string, content_string, condition):
    #Create the windows executable file object
    winexecobj = winexecutablefileobj.WindowsExecutableFileObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "FileItem/PEInfo/BaseAddress" or search_string == "DriverItem/PEInfo/BaseAddress":
        pehead = winexecutablefileobj.PEHeadersType()
        opthead = winexecutablefileobj.PEOptionalHeaderType()
        opthead.set_Base_Of_Code(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        pehead.set_Optional_Header(opthead)
        winexecobj.set_Headers(pehead)
    elif search_string == "FileItem/PEInfo/DetectedAnomalies/string":
        valueset = False
    elif search_string == "FileItem/PEInfo/DetectedEntryPointSignature/Name" or search_string == "DriverItem/PEInfo/DetectedEntryPointSignature/Name":
        packerlist = fileobj.PackerListType()
        packer = fileobj.PackerType()
        epsiglist = fileobj.EntryPointSignatureListType()
        epsig = fileobj.EntryPointSignatureType()
        epsig.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        epsiglist.add_Entry_Point_Signature(epsig)
        packer.set_Detected_Entrypoint_Signatures(epsiglist)
        packerlist.add_Packer(packer)
        winexecobj.set_Packer_List(packerlist)
    elif search_string == "FileItem/PEInfo/DetectedEntryPointSignature/Type" or search_string == "DriverItem/PEInfo/DetectedEntryPointSignature/Type":
        packerlist = fileobj.PackerListType()
        packer = fileobj.PackerType()
        epsiglist = fileobj.EntryPointSignatureListType()
        epsig = fileobj.EntryPointSignatureType()
        epsig.set_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        epsiglist.add_Entry_Point_Signature(epsig)
        packer.set_Detected_Entrypoint_Signatures(epsiglist)
        packerlist.add_Packer(packer)
        winexecobj.set_Packer_List(packerlist)
    elif search_string == "FileItem/PEInfo/DigitalSignature/CertificateIssuer" or search_string == "DriverItem/PEInfo/DigitalSignature/CertificateIssuer":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Certificate_Issuer(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        winexecobj.set_Digital_Signature(digital_signature)
    elif search_string == "FileItem/PEInfo/DigitalSignature/CertificateSubject" or search_string == "DriverItem/PEInfo/DigitalSignature/CertificateSubject":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Certificate_Subject(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        winexecobj.set_Digital_Signature(digital_signature)
    elif search_string == "FileItem/PEInfo/DigitalSignature/Description" or search_string == "DriverItem/PEInfo/DigitalSignature/Description":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Signature_Description(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        winexecobj.set_Digital_Signature(digital_signature)
    elif search_string == "FileItem/PEInfo/DigitalSignature/SignatureExists" or search_string == "DriverItem/PEInfo/DigitalSignature/SignatureExists":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_signature_exists(content_string)
        winexecobj.set_Digital_Signature(digital_signature)
    elif search_string == "FileItem/PEInfo/DigitalSignature/SignatureVerified" or search_string == "DriverItem/PEInfo/DigitalSignature/SignatureVerified":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_signature_verified(content_string)
        winexecobj.set_Digital_Signature(digital_signature)
    elif search_string == "FileItem/PEInfo/EpJumpCodes/Depth" or search_string == "DriverItem/PEInfo/EpJumpCodes/Depth":
        packerlist = fileobj.PackerListType()
        packer = fileobj.PackerType()
        epjumpcode = fileobj.EPJumpCodeType()
        epjumpcode.set_Depth(process_numerical_value(common.IntegerObjectPropertyType(datatype=None, ), content_string, condition))
        packer.set_EP_Jump_Codes(epjumpcode)
        packerlist.add_Packer(packer)
        winexecobj.set_Packer_List(packerlist)
    elif search_string == "FileItem/PEInfo/EpJumpCodes/Opcodes" or search_string == "DriverItem/PEInfo/EpJumpCodes/Opcodes":
        packerlist = fileobj.PackerListType()
        packer = fileobj.PackerType()
        epjumpcode = fileobj.EPJumpCodeType()
        epjumpcode.set_Opcodes(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        packer.set_EP_Jump_Codes(epjumpcode)
        packerlist.add_Packer(packer)
        winexecobj.set_Packer_List(packerlist)
    elif search_string == "FileItem/PEInfo/Exports/DllName":
        valueset = False
    elif search_string == "FileItem/PEInfo/Exports/ExportedFunctions/string" or search_string == "DriverItem/PEInfo/Exports/ExportedFunctions/string":
        exports = winexecutablefileobj.PEExportsType()
        exportfunlist = winexecutablefileobj.PEExportedFunctionsType()
        exportfun = winexecutablefileobj.PEExportedFunctionType()
        exportfun.set_Function_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        exportfunlist.add_Exported_Function(exportfun)
        exports.set_Exported_Functions(exportfunlist)
        winexecobj.set_Exports(exports)
    elif search_string == "FileItem/PEInfo/Exports/ExportsTimeStamp" or search_string == "DriverItem/PEInfo/Exports/ExportsTimeStamp":
        exports = winexecutablefileobj.PEExportsType()
        exports.set_Exports_Time_Stamp(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        winexecobj.set_Exports(exports)
    elif search_string == "FileItem/PEInfo/Exports/NumberOfFunctions":
        valueset = False
    elif search_string == "FileItem/PEInfo/Exports/NumberOfNames" or search_string == "DriverItem/PEInfo/Exports/NumberOfNames":
        exports = winexecutablefileobj.PEExportsType()
        exports.set_Number_Of_Names(process_numerical_value(common.IntegerObjectPropertyType(datatype=None), content_string, condition))
        winexecobj.set_Exports(exports)
    elif search_string == "FileItem/PEInfo/ExtraneousBytes" or search_string == "DriverItem/PEInfo/ExtraneousBytes":
        winexecobj.set_Extraneous_Bytes(process_numerical_value(common.IntegerObjectPropertyType(datatype=None), content_string, condition))
    elif search_string == "FileItem/PEInfo/ImportedModules/Module/ImportedFunctions/string" or search_string == "DriverItem/PEInfo/ImportedModules/Module/ImportedFunctions/string":
        imports = winexecutablefileobj.PEImportListType()
        peimport = winexecutablefileobj.PEImportType()
        importfunlist = winexecutablefileobj.PEImportedFunctionsType()
        importfun = winexecutablefileobj.PEImportedFunctionType()
        importfun.set_Function_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        importfunlist.add_Imported_Function(importfun)
        peimport.set_Imported_Functions(importfunlist)
        imports.add_Import(peimport)
        winexecobj.set_Imports(imports)
    elif search_string == "FileItem/PEInfo/ImportedModules/Module/Name" or search_string == "DriverItem/PEInfo/ImportedModules/Module/Name":
        imports = winexecutablefileobj.PEImportListType()
        peimport = winexecutablefileobj.PEImportType()
        peimport.set_File_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        imports.add_Import(peimport)
        winexecobj.set_Imports(imports)
    elif search_string == "FileItem/PEInfo/ImportedModules/Module/NumberOfFunctions":
        valueset = False
    elif search_string == "FileItem/PEInfo/PEChecksum/PEComputedAPI" or search_string == "DriverItem/PEInfo/PEChecksum/PEComputedAPI":
        checksum = winexecutablefileobj.PEChecksumType()
        checksum.set_PE_Computed_API(process_numerical_value(common.LongObjectPropertyType(datatype=None), content_string, condition))
        winexecobj.set_PE_Checksum(checksum)
    elif search_string == "FileItem/PEInfo/PEChecksum/PEFileAPI" or search_string == "DriverItem/PEInfo/PEChecksum/PEFileAPI":
        checksum = winexecutablefileobj.PEChecksumType()
        checksum.set_PE_File_API(process_numerical_value(common.LongObjectPropertyType(datatype=None), content_string, condition))
        winexecobj.set_PE_Checksum(checksum)
    elif search_string == "FileItem/PEInfo/PEChecksum/PEFileRaw" or search_string == "DriverItem/PEInfo/PEChecksum/PEFileRaw":
        checksum = winexecutablefileobj.PEChecksumType()
        checksum.set_PE_File_Raw(process_numerical_value(common.LongObjectPropertyType(datatype=None), content_string, condition))
        winexecobj.set_PE_Checksum(checksum)
    elif search_string == "FileItem/PEInfo/PETimeStamp" or search_string == "DriverItem/PEInfo/PETimeStamp":
        headers = winexecutablefileobj.PEHeadersType()
        fileheader = winexecutablefileobj.PEFileHeaderType()
        fileheader.set_Time_Date_Stamp(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
        headers.set_File_Header(fileheader)
        winexecobj.set_Headers(headers)
    elif search_string == "FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Data":
        valueset = False
    elif search_string == "FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Language":
        valueset = False
    elif search_string == "FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Name":
        reslist = winexecutablefileobj.PEResourceListType()
        res = winexecutablefileobj.PEResourceType()
        res.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(res)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Size":
        valueset = False
    elif search_string == "FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Type":
        reslist = winexecutablefileobj.PEResourceListType()
        res = winexecutablefileobj.PEResourceType()
        res.set_Type(process_string_value(content_string))
        reslist.add_Resource(res)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/Sections/NumberOfSections":
        valueset = False
    elif search_string == "FileItem/PEInfo/Sections/ActualNumberOfSections":
        valueset = False
    elif search_string == "FileItem/PEInfo/Sections/Section/DetectedCharacteristics" or search_string == "DriverItem/PEInfo/Sections/Section/DetectedCharacteristics":
        seclist = winexecutablefileobj.PESectionListType()
        sec = winexecutablefileobj.PESectionType()
        sechdr = winexecutablefileobj.PESectionHeaderStructType()
        sechdr.set_Characteristics(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        sec.set_Section_Header(sechdr)
        seclist.add_Section(sec)
        winexecobj.set_Sections(seclist)
    elif search_string == "FileItem/PEInfo/Sections/Section/DetectedSignatureKeys/string":
        valueset = False
    elif search_string == "FileItem/PEInfo/Sections/Section/Entropy/CurveData/float":
        valueset = False
    elif search_string == "FileItem/PEInfo/Sections/Section/Name" or search_string == "DriverItem/PEInfo/Sections/Section/Name":
        seclist = winexecutablefileobj.PESectionListType()
        sec = winexecutablefileobj.PESectionType()
        sechdr = winexecutablefileobj.PESectionHeaderStructType()
        sechdr.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        sec.set_Section_Header(sechdr)
        seclist.add_Section(sec)
        winexecobj.set_Sections(seclist)
    elif search_string == "FileItem/PEInfo/Sections/Section/SizeInBytes":
        valueset = False
    elif search_string == "FileItem/PEInfo/Sections/Section/Type" or search_string == "DriverItem/PEInfo/Sections/Section/Type":
        seclist = winexecutablefileobj.PESectionListType()
        sec = winexecutablefileobj.PESectionType()
        sec.set_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        seclist.add_Section(sec)
        winexecobj.set_Sections(seclist)
    elif search_string == "FileItem/PEInfo/Subsystem" or search_string == "DriverItem/PEInfo/Subsystem":
        pehead = winexecutablefileobj.PEHeadersType()
        opthead = winexecutablefileobj.PEOptionalHeaderType()
        opthead.set_Subsystem(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        pehead.set_Optional_Header(opthead)
        winexecobj.set_Headers(pehead)
    elif search_string == "FileItem/PEInfo/Type" or search_string == "DriverItem/PEInfo/Type":
        petype = winexecutablefileobj.PEType()
        petype.set_valueOf_(process_string_value(content_string))
        petype.set_datatype('string')
        winexecobj.set_Type(petype)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/Comments":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_Comments(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/CompanyName":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_CompanyName(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileDescription":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_FileDescription(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileVersion":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_FileVersion(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/InternalName":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_InternalName(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/Language":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_LangID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/LegalCopyright":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_LegalCopyright(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/LegalTrademarks":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_LegalTrademarks(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/OriginalFilename":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_OriginalFilename(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/PrivateBuild":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_PrivateBuild(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/ProductName":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_ProductName(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/ProductVersion":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_ProductVersion(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/SpecialBuild":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_SpecialBuild(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)

    if valueset:
        winexecobj.set_xsi_type('WinExecutableFileObj:WindowsExecutableFileObjectType')
    elif not valueset:
        winexecobj = None
    
    return winexecobj

def createWinUserObj(search_string, content_string, condition):
    #Create the win user account object
    accountobj = winuseraccountobj.WindowsUserAccountObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True
    
    if search_string == "UserItem/SecurityID":
        accountobj.set_Security_ID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "UserItem/SecurityType":
        accountobj.set_Security_Type(common.StringObjectPropertyType(datatype='string', condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        accountobj.set_xsi_type('WinUserAccountObj:WindowsUserAccountObjectType')
    elif not valueset:
        accountobj = None
    
    return accountobj

def createAccountObj(search_string, content_string, condition):
    #Create the account object
    acctobj = accountobj.AccountObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "UserItem/description":
        acctobj.set_Description(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "UserItem/disabled":
        acctobj.set_disabled(content_string)
    elif search_string == "UserItem/lockedout":
        acctobj.set_locked_out(content_string)

    if valueset:
        acctobj.set_xsi_type('AccountObj:AccountObjectType')
    elif not valueset:
        acctobj = None
    
    return acctobj
 
def createWinMemoryPageObj(search_string, content_string, condition):
    #Create the windows memory page region object
    wmpobj = winmemorypageregionobj.WindowsMemoryPageRegionObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True

    if search_string == "ProcessItem/SectionList/MemorySection/Protection":
        wmpobj.set_Protect(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        wmpobj.set_xsi_type('WinMemoryPageRegionObj:WindowsMemoryPageRegionObjectType')
    elif not valueset:
        wmpobj = None
    
    return wmpobj
    
def createWinProcessObj(search_string, content_string, condition):
    #Create the Win process object
    winprocobj = winprocessobj.WindowsProcessObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True
        
    if search_string == "ProcessItem/HandleList/Handle/AccessMask":
        handle_list = winhandleobj.WindowsHandleListType()
        handle = winhandleobj.WindowsHandleObjectType()
        handle.set_Access_Mask(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
        handle_list.add_Handle(handle)
        winprocobj.set_Handle_List(handle_list) 
    elif search_string == "ProcessItem/HandleList/Handle/HandleCount":
        valueset = False
    elif search_string == "ProcessItem/HandleList/Handle/Index":
        handle_list = winhandleobj.WindowsHandleListType()
        handle = winhandleobj.WindowsHandleObjectType()
        handle.set_ID(process_numerical_value(common.UnsignedIntegerObjectPropertyType(datatype=None), content_string, condition))
        handle_list.add_Handle(handle)
        winprocobj.set_Handle_List(handle_list)
    elif search_string == "ProcessItem/HandleList/Handle/Name":
        handle_list = winhandleobj.WindowsHandleListType()
        handle = winhandleobj.WindowsHandleObjectType()
        handle.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        handle_list.add_Handle(handle)
        winprocobj.set_Handle_List(handle_list)
    elif search_string == "ProcessItem/HandleList/Handle/ObjectAddress":
        handle_list = winhandleobj.WindowsHandleListType()
        handle = winhandleobj.WindowsHandleObjectType()
        handle.set_Object_Address(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
        handle_list.add_Handle(handle)
        winprocobj.set_Handle_List(handle_list)
    elif search_string == "ProcessItem/HandleList/Handle/PointerCount":
        handle_list = winhandleobj.WindowsHandleListType()
        handle = winhandleobj.WindowsHandleObjectType()
        handle.set_Pointer_Count(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
        handle_list.add_Handle(handle)
        winprocobj.set_Handle_List(handle_list)
    elif search_string == "ProcessItem/HandleList/Handle/Type":
        handle_list = winhandleobj.WindowsHandleListType()
        handle = winhandleobj.WindowsHandleObjectType()
        handle.set_Type(common.StringObjectPropertyType(datatype='string', condition=condition, valueOf_=process_string_value(content_string)))
        handle_list.add_Handle(handle)
        winprocobj.set_Handle_List(handle_list)
    elif search_string.count("DigitalSignature") > 0:
        valueset = False
    elif search_string == "ProcessItem/SectionList/MemorySection/Injected":
        memory_section_list = winprocessobj.MemorySectionListType()
        memory_section = memoryobj.MemoryObjectType()
        memory_section.set_is_injected(content_string)
        memory_section_list.add_Memory_Section(memory_section)
        winprocobj.set_Section_List(memory_section_list)
    elif search_string == "ProcessItem/SectionList/MemorySection/Mapped":
        memory_section_list = winprocessobj.MemorySectionListType()
        memory_section = memoryobj.MemoryObjectType()
        memory_section.set_is_mapped(content_string)
        memory_section_list.add_Memory_Section(memory_section)
        winprocobj.set_Section_List(memory_section_list)
    elif search_string == "ProcessItem/SectionList/MemorySection/Md5sum":
        hashes = common.HashListType()
        md5hash = common.HashType()
        md5hash.set_Type(common.ControlledVocabularyStringType(valueOf_='MD5', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        md5hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        hashes.add_Hash(md5hash)
        memory_section_list = winprocessobj.MemorySectionListType()
        memory_section = memoryobj.MemoryObjectType()
        memory_section.set_Hashes(hashes)
        memory_section_list.add_Memory_Section(memory_section)
        winprocobj.set_Section_List(memory_section_list)
    elif search_string == "ProcessItem/SectionList/MemorySection/Name":
        memory_section_list = winprocessobj.MemorySectionListType()
        memory_section = memoryobj.MemoryObjectType()
        memory_section.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
        memory_section_list.add_Memory_Section(memory_section)
        winprocobj.set_Section_List(memory_section_list)
    elif search_string.count("PEInfo") > 0:
        return createWinExecObj(search_string, content_string, condition)
    elif search_string == "ProcessItem/SectionList/MemorySection/Protection":
        createWinMemoryPageObj(search_string, content_string, condition)
    elif search_string == "ProcessItem/SectionList/MemorySection/RawFlags":
        valueset = False
    elif search_string == "ProcessItem/SectionList/MemorySection/RegionSize":
        memory_section_list = winprocessobj.MemorySectionListType()
        memory_section = memoryobj.MemoryObjectType()
        memory_section.set_Region_Size(process_numerical_value(common.UnsignedLongObjectPropertyType(datatype=None), content_string, condition))
        memory_section_list.add_Memory_Section(memory_section)
        winprocobj.set_Section_List(memory_section_list)
    elif search_string == "ProcessItem/SectionList/MemorySection/RegionStart":
        memory_section_list = winprocessobj.MemorySectionListType()
        memory_section = memoryobj.MemoryObjectType()
        memory_section.set_Region_Start_Address(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        memory_section_list.add_Memory_Section(memory_section)
        winprocobj.set_Section_List(memory_section_list)
    elif search_string == "ProcessItem/SectionList/MemorySection/Sha1Sum":
        hashes = common.HashListType()
        sha1hash = common.HashType()
        sha1hash.set_Type(common.ControlledVocabularyStringType(valueOf_='SHA1', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        sha1hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        hashes.add_Hash(sha1hash)
        memory_section_list = winprocessobj.MemorySectionListType()
        memory_section = memoryobj.MemoryObjectType()
        memory_section.set_Hashes(hashes)
        memory_section_list.add_Memory_Section(memory_section)
        winprocobj.set_Section_List(memory_section_list)
    elif search_string == "ProcessItem/SectionList/MemorySection/Sha256Sum":
        hashes = common.HashListType()
        sha256hash = common.HashType()
        sha256hash.set_Type(common.ControlledVocabularyStringType(valueOf_='SHA256', xsi_type='cyboxVocabs:HashNameVocab-1.0'))
        sha256hash.set_Simple_Hash_Value(process_numerical_value(common.HexBinaryObjectPropertyType(datatype=None), content_string, condition))
        hashes.add_Hash(sha256hash)
        memory_section_list = winprocessobj.MemorySectionListType()
        memory_section = memoryobj.MemoryObjectType()
        memory_section.set_Hashes(hashes)
        memory_section_list.add_Memory_Section(memory_section)
        winprocobj.set_Section_List(memory_section_list)
    elif search_string == "ProcessItem/SecurityID":
        winprocobj.set_Security_ID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))
    elif search_string == "ProcessItem/SecurityType":
        winprocobj.set_Security_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=process_string_value(content_string)))

    if valueset:
        winprocobj.set_xsi_type('WinProcessObj:WindowsProcessObjectType')
    elif not valueset:
        winprocobj = None

    return winprocobj
    

#Set the correct attributes for any range values

def process_numerical_value(object_attribute, content_string, condition):
    if content_string.count('[') > 0 or content_string.count(' TO ') > 0:
        normalized_string = content_string.strip('[]')
        split_string = normalized_string.split(' TO ')
        object_attribute.set_condition('InclusiveBetween')
        object_attribute.set_valueOf_(split_string[0] + ',' + split_string[1])
        if condition == 'Contains' or condition == 'Equals':           
            object_attribute.set_apply_condition('ANY')
        elif condition == 'DoesNotContain' or condition == 'DoesNotEqual':
            object_attribute.set_apply_condition('NONE')
    else:
        object_attribute.set_condition(condition)
        object_attribute.set_valueOf_(content_string)
    return object_attribute

#Encase any strings with XML escape characters in the proper tags

def process_string_value(content_string):
    if (
    content_string.count('<') > 0 or
    content_string.count('>') > 0 or
    content_string.count("'") > 0 or
    content_string.count('"') > 0 or
    content_string.count('&') > 0 
    ):
        return ('<![CDATA[' + content_string + ']]>')
    else:
        return content_string.replace(',','&#44;')
