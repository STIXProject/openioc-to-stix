# Copyright (c) 2017, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import logging

# external
from cybox.core import Object

# internal
from . import xml, utils

# Module logger
LOG = logging.getLogger(__name__)


def _assert_field(obj, attrname):
    klass = obj.__class__

    if hasattr(obj, attrname):
        return

    if hasattr(klass, attrname):
        return

    raise AttributeError("Object has no attribute: %s" % attrname)


def _set_field(obj, attrname, value, condition=None):

    # Set the attribute
    setattr(obj, attrname, xml.sanitize(value))

    attr = getattr(obj, attrname)

    if hasattr(attr, 'condition') and condition:
        attr.condition = condition

    return attr


def _set_numeric_field(obj, attrname, value, condition=None):
    # Remove any braces if they exist (sometimes they do)
    stripped  = value.strip('[]')

    # Split on ' TO ', which can be used in Indicators to designate ranges.
    values    = stripped.split(' TO ')

    if len(values) == 1:
        return _set_field(obj, attrname, values[0], condition)

    # ' TO ' found. This is a range.
    field = _set_field(obj, attrname, values, "InclusiveBetween")

    if condition in ('Contains', 'Equals'):
        field.apply_condition = "ANY"
    elif condition in ("DoesNotContain", "DoesNotEqual"):
        field.apply_condition = "NONE"
    else:
        field.apply_condition = "ALL"  # TODO: Is this correct?

    return field


def set_field(obj, attrname, value, condition=None):
    _assert_field(obj, attrname)

    if utils.is_numeric(obj, attrname):
        return _set_numeric_field(obj, attrname, value, condition)
    else:
        return _set_field(obj, attrname, value, condition)


def has_content(obj):
    if not hasattr(obj, '_fields'):
        return False

    return any(x for x in obj._fields.itervalues())


## primary object functions

def create_disk_obj(search_string, content_string, condition):
    from cybox.objects.disk_object import Disk, DiskPartition, PartitionList

    disk = Disk()
    part = DiskPartition()

    disk_attrmap = {
        "DiskItem/DiskName": "disk_name",
        "DiskItem/DiskSize": "disk_size"
    }

    part_attrmap = {
        "DiskItem/PartitionList/Partition/PartitionLength": "partition_length",
        "DiskItem/PartitionList/Partition/PartitionNumber": "partition_id",
        "DiskItem/PartitionList/Partition/PartitionOffset": "partition_offset",
        "DiskItem/PartitionList/Partition/PartitionType": "partition_type"
    }

    if search_string in disk_attrmap:
        set_field(disk, disk_attrmap[search_string], content_string, condition)
    elif search_string in part_attrmap:
        set_field(part, part_attrmap[search_string], content_string, condition)
        disk.partition_list = PartitionList(part)
    else:
        return None

    return Object(disk)

def create_dns_obj(search_string, content_string, condition):
    from cybox.objects.dns_record_object import DNSRecord
    from cybox.objects.dns_cache_object import DNSCache, DNSCacheEntry

    cache = DNSCache()
    record = DNSRecord()

    attrmap = {
        "DnsEntryItem/DataLength": "data_length",
        "DnsEntryItem/Flags": "flags",
        "DnsEntryItem/Host": "domain_name",
        "DnsEntryItem/RecordData/Host": "record_data",
        "DnsEntryItem/RecordData/IPv4Address": "record_data",
        "DnsEntryItem/RecordName": "record_name",
        "DnsEntryItem/RecordType": "record_type",
        "DnsEntryItem/TimeToLive": "ttl"
    }

    if search_string in attrmap:
        set_field(record, attrmap[search_string], content_string, condition)
    else:
        return None

    entry = DNSCacheEntry()
    entry.dns_entry = record
    cache.dns_cache_entry = entry

    return Object(cache)

def create_driver_obj(search_string, content_string, condition):
    from cybox.objects.win_driver_object import WinDriver, DeviceObjectStruct, DeviceObjectList

    windriver = WinDriver()
    device = DeviceObjectStruct()

    device_attrmap = {
        "DriverItem/DeviceItem/AttachedDeviceName": "attached_device_name",
        "DriverItem/DeviceItem/AttachedDeviceObject": "attached_device_object",
        "DriverItem/DeviceItem/AttachedToDeviceName": "attached_to_device_name",
        "DriverItem/DeviceItem/AttachedToDeviceObject": "attached_to_device_object",
        "DriverItem/DeviceItem/AttachedToDriverName": "attached_to_driver_name",
        "DriverItem/DeviceItem/AttachedToDriverObject": "attached_to_driver_object",
        "DriverItem/DeviceItem/DeviceName": "device_name",
        "DriverItem/DeviceItem/DeviceObject": "device_object"
    }

    driver_attrmap = {
        "DriverItem/DriverInit": "driver_init",
        "DriverItem/DriverName": "driver_name",
        "DriverItem/DriverObjectAddress": "driver_object_address",
        "DriverItem/DriverStartIo": "driver_start_io",
        "DriverItem/DriverUnload": "driver_unload",
        "DriverItem/ImageBase": "image_base",
        "DriverItem/ImageSize": "image_size"
    }

    file_keys = (
        "DriverItem/Sha1sum",
        "DriverItem/Sha256sum",
        "DriverItem/StringList/string"
    )

    if "/PEInfo/" in search_string:
        return create_pefile_obj(search_string, content_string, condition)
    if search_string in file_keys:
        return create_file_obj(search_string, content_string, condition)
    elif search_string in device_attrmap:
        set_field(device, device_attrmap[search_string], content_string, condition)
        windriver.device_object_list = DeviceObjectList(device)
    elif search_string in driver_attrmap:
        set_field(windriver, driver_attrmap[search_string], content_string, condition)
    else:
        return None

    return Object(windriver)

def create_email_obj(search_string, content_string, condition):
    from cybox.objects.file_object import File
    from cybox.objects.email_message_object import (
        Attachments, EmailMessage, EmailHeader, ReceivedLine, ReceivedLineList
    )

    email       = EmailMessage()
    header      = EmailHeader()
    received    = ReceivedLine()
    attachment  = None

    file_attrmap = {
        "Email/Attachment/Name": "file_name",
        "Email/Attachment/SizeInBytes": "size_in_bytes"
    }

    email_attrmap = {
        "Email/Body": "raw_body",
        "Email/EmailServer": "email_server"  # Not a standard OpenIOC indicator term
    }

    received_attrmap = {
        "Email/Received": "timestamp",
        "Email/ReceivedFromHost": "from_",
        "Email/ReceivedFromIP": "from_"

    }

    header_attrmap = {
        "Email/BCC": "bcc",
        "Email/CC": "cc",
        "Email/Content-Type": "content_type",
        "Email/Date": "date",
        "Email/From": "from_",
        "Email/In-Reply-To": "in_reply_to",
        "Email/MIME-Version": "mime_version",
        "Email/Subject": "subject",
        "Email/To": "to",
        "Email/ReplyTo": "reply_to"  # Not a standard OpenIOC indicator term
    }

    if search_string in email_attrmap:
        set_field(email, email_attrmap[search_string], content_string, condition)
    elif search_string in file_attrmap:
        attachment = File()
        set_field(attachment, file_attrmap[search_string], content_string, condition)
        email.attachments = Attachments(attachment.parent.id_)
    elif search_string in header_attrmap:
        set_field(header, header_attrmap[search_string], content_string, condition)
        email.header = header
    elif search_string in received_attrmap:
        set_field(received, received_attrmap[search_string], content_string, condition)
        header.received_lines = ReceivedLineList(received)
    else:
        return None

    if not attachment:
        return Object(email)

    email = Object(email)
    email.add_related(attachment, "Contains")

    return email


def create_win_event_log_obj(search_string, content_string, condition):
    from cybox.common.properties import String
    from cybox.objects.win_event_log_object import WinEventLog, UnformattedMessageList

    eventlog = WinEventLog()

    attrmap = {
        "EventLogItem/CorrelationActivityId": "correlation_activity_id",
        "EventLogItem/CorrelationRelatedActivityId": "correlation_related_activity_id",
        "EventLogItem/EID": "eid",
        "EventLogItem/ExecutionProcessId": "execution_process_id",
        "EventLogItem/ExecutionThreadId": "execution_thread_id",
        "EventLogItem/blob": "blob",
        "EventLogItem/category": "category",
        "EventLogItem/categoryNum": "category_num",
        "EventLogItem/genTime": "generation_time",
        "EventLogItem/index": "index",
        "EventLogItem/log": "log",
        "EventLogItem/machine": "machine",
        "EventLogItem/message": "message",
        "EventLogItem/reserved": "reserved",
        "EventLogItem/source": "source",
        "EventLogItem/type": "type_",
        "EventLogItem/user": "user",
        "EventLogItem/writeTime": "write_time"
    }

    if search_string in attrmap:
        set_field(eventlog, attrmap[search_string], content_string, condition)
    elif search_string == "EventLogItem/unformattedMessage/string":
        s = String(xml.sanitize(content_string))
        s.condition = condition
        eventlog.unformatted_message_list = UnformattedMessageList(s)
    else:
        return None

    return Object(eventlog)

def create_file_obj(search_string, content_string, condition):
    from cybox.objects.file_object import File
    from cybox.common import ExtractedStrings, ExtractedFeatures

    f = File()

    attrmap = {
        "FileItem/Accessed": "accessed_time",
        "FileItem/Created": "created_time",
        "FileItem/DevicePath": "device_path",
        "FileItem/FileExtension": "file_extension",
        "FileItem/FileName": "file_name",
        "FileItem/FilePath": "file_path",
        "FileItem/FullPath": "full_path",
        "FileItem/Md5sum": "md5",
        "FileItem/Sha256sum": "sha256",
        "FileItem/Sha1sum": "sha1",
        "DriverItem/Sha1sum": "sha1",
        "DriverItem/Md5sum": "md5",
        "DriverItem/Sha256sum": "sha256",
        "FileItem/Modified": "modified_time",
        "FileItem/PeakEntropy": "peak_entropy",
        "FileItem/SizeInBytes": "size_in_bytes",
        "FileItem/Username": "user_owner"
    }

    winfile_keys = (
        "FileItem/Drive",
        "FileItem/FileAttributes",
        "FileItem/FilenameAccessed",
        "FileItem/FilenameCreated",
        "FileItem/FilenameModified",
        "FileItem/SecurityID",
        "FileItem/SecurityType",
        "FileItem/StreamList/Stream/Md5sum",
        "FileItem/StreamList/Stream/Name",
        "FileItem/StreamList/Stream/Sha1sum",
        "FileItem/StreamList/Stream/Sha256sum",
        "FileItem/StreamList/Stream/SizeInBytes"
    )

    if search_string in attrmap:
        set_field(f, attrmap[search_string], content_string, condition)
    elif search_string in winfile_keys:
        return create_win_file_obj(search_string, content_string, condition)
    elif search_string == "FileItem/INode":
        return create_unix_file_obj(search_string, content_string, condition)
    elif '/PEInfo/' in search_string:
        return create_pefile_obj(search_string, content_string, condition)
    elif "/StringList/string" in search_string:
        extracted_features = ExtractedFeatures()
        extracted_features.strings = ExtractedStrings(xml.sanitize(content_string))
        f.extracted_features = extracted_features
    else:
        return None

    return Object(f)

def create_hook_obj(search_string, content_string, condition):
    from cybox.objects.win_kernel_hook_object import WinKernelHook
    from cybox.common.digitalsignature import DigitalSignature

    hook = WinKernelHook()
    ds = DigitalSignature()

    hook_attrmap = {
        "HookItem/HookDescription": "hook_description",
        "HookItem/HookedFunction": "hooked_function",
        "HookItem/HookedModule": "hooked_module",
        "HookItem/HookingAddress": "hooking_address",
        "HookItem/HookingModule": "hooking_module"
    }

    ds_attrmap = {
        "HookItem/DigitalSignatureHooking/CertificateIssuer": "certificate_issuer",
        "HookItem/DigitalSignatureHooking/CertificateSubject": "certificate_subject",
        "HookItem/DigitalSignatureHooking/Description": "signature_description",
        "HookItem/DigitalSignatureHooking/SignatureExists": "signature_exists",
        "HookItem/DigitalSignatureHooking/SignatureVerified": "signature_verified",
        "HookItem/DigitalSignatureHooked/CertificateIssuer": "certificate_issuer",
        "HookItem/DigitalSignatureHooked/CertificateSubject": "certificate_subject",
        "HookItem/DigitalSignatureHooked/Description": "signature_description",
        "HookItem/DigitalSignatureHooked/SignatureExists": "signature_exists",
        "HookItem/DigitalSignatureHooked/SignatureVerified": "signature_verified"
    }

    if search_string in ds_attrmap:
        set_field(ds, ds_attrmap[search_string], content_string, condition)

        if "DigitalSignatureHooking" in search_string:
            hook.digital_signature_hooking = ds
        else:
            hook.digital_signature_hooked = ds
    elif search_string in hook_attrmap:
        set_field(hook, hook_attrmap[search_string], content_string, condition)
    else:
        return None

    return Object(hook)

def create_library_obj(search_string, content_string, condition):
    from cybox.objects.library_object import Library

    attrmap = {
        "ModuleItem/ModuleBase": "base_address",
        "ModuleItem/ModuleName": "name",
        "ModuleItem/ModulePath": "path",
        "ModuleItem/ModuleSize": "size"
    }

    library = Library()

    if search_string in attrmap:
        set_field(library, attrmap[search_string], content_string, condition)
    else:
        return None

    return Object(library)


def create_network_connection_obj(search_string, content_string, condition):
    from cybox.objects.socket_address_object import SocketAddress
    from cybox.objects.network_connection_object import (
        NetworkConnection, Layer7Connections
    )
    from cybox.objects.http_session_object import (
        HTTPSession, HTTPClientRequest, HTTPRequestResponse, HTTPRequestHeader,
        HTTPRequestHeaderFields, HostField, HTTPRequestLine
    )

    # HTTP Session stuff
    session = HTTPSession()
    request_response = HTTPRequestResponse()
    request = HTTPClientRequest()
    request_line = HTTPRequestLine()
    header = HTTPRequestHeader()
    header_fields = HTTPRequestHeaderFields()

    # Network Connection stuff
    layer7 = Layer7Connections()
    socketaddr = SocketAddress()
    net = NetworkConnection()

    # Pre-wire common HTTP Session properties
    layer7.http_session = session
    session.http_request_response = request_response
    request_response.http_client_request = request
    request.http_request_header = header

    socket_attrmap = {
        "PortItem/localIP": ("ip_address", "source_socket_address"),
        "PortItem/remoteIP": ("ip_address", "destination_socket_address"),
        "ProcessItem/PortList/PortItem/localIP": ("ip_address", "source_socket_address"),
    }

    if search_string in socket_attrmap:
        socket_field, net_field = socket_attrmap[search_string]
        set_field(socketaddr, socket_field, content_string, condition)
        set_field(net, net_field, socketaddr)
    elif search_string == "Network/DNS":
        host = HostField()
        header_fields.host = host
        header.parsed_header = header_fields
        set_field(host, "domain_name", content_string, condition)
    elif search_string == "Network/HTTP_Referer":
        set_field(header_fields, "referer", content_string, condition)
        header.parsed_header = header_fields
    elif search_string == "Network/String":
        set_field(header, "raw_header", content_string, condition)
    elif search_string == "Network/URI":
        set_field(request_line, "value", content_string, condition)
        request.http_request_line = request_line
    elif search_string == "Network/UserAgent":
        set_field(header_fields, "user_agent", content_string, condition)
        header.parsed_header = header_fields
    elif "PortItem/CreationTime" in search_string:
        set_field(net, "creation_time", content_string, condition)
    else:
        return None

    return Object(net)

def create_net_route_obj(search_string, content_string, condition):
    from cybox.objects.network_route_entry_object import NetworkRouteEntry
    from cybox.objects.address_object import Address

    net  = NetworkRouteEntry()
    addr = Address(category=Address.CAT_IPV4)

    addr_keys = set([
        "RouteEntryItem/Destination",
        "RouteEntryItem/Gateway",
        "RouteEntryItem/Netmask"
    ])

    attr_map = {
        "RouteEntryItem/Destination": "destination_address",
        "RouteEntryItem/Gateway": "gateway_address",
        "RouteEntryItem/Interface": "interface",
        "RouteEntryItem/IsIPv6": "is_ipv6",
        "RouteEntryItem/Metric": "metric",
        "RouteEntryItem/Netmask": "netmask",
        "RouteEntryItem/Protocol": "protocol",
        "RouteEntryItem/RouteAge": "route_age",
        "RouteEntryItem/RouteType": "route_type"
    }

    if search_string in addr_keys:
        set_field(addr, "address_value", content_string, condition)
        set_field(net, attr_map[search_string], addr)
    elif search_string in attr_map:
        set_field(net, attr_map[search_string], content_string, condition)
    else:
        return None

    return Object(net)


def create_port_obj(search_string, content_string, condition):
    from cybox.objects.port_object import Port

    port = Port()

    netconn_keys = (
        "PortItem/CreationTime",
        "PortItem/localIP",
        "PortItem/remoteIP"
    )

    attrmap = {
        "PortItem/localPort": "port_value",
        "PortItem/remotePort": "port_value",
        "PortItem/protocol": "layer4_protocol"
    }

    if search_string in attrmap:
        set_field(port, attrmap[search_string], content_string, condition)
    elif search_string in netconn_keys:
        return create_network_connection_obj(search_string, content_string, condition)
    else:
        return None

    return Object(port)

def create_prefetch_obj(search_string, content_string, condition):
    from cybox.common.properties import String
    from cybox.objects.win_volume_object import WinVolume
    from cybox.objects.win_prefetch_object import WinPrefetch, AccessedFileList

    prefected_attrmap = {
        "PrefetchItem/ApplicationFileName": "application_file_name",
        "PrefetchItem/LastRun": "last_run",
        "PrefetchItem/PrefetchHash": "prefetch_hash",
        "PrefetchItem/TimesExecuted": "times_executed",
    }

    volume_attrmap = {
        "PrefetchItem/VolumeList/VolumeItem/DevicePath": "device_path",
        "PrefetchItem/VolumeList/VolumeItem/CreationTime": "creation_time",
        "PrefetchItem/VolumeList/VolumeItem/SerialNumber": "serial_number"
    }

    prefetch = WinPrefetch()
    # volume = WinVolume()

    if search_string in prefected_attrmap:
        set_field(prefetch, prefected_attrmap[search_string], content_string, condition)
    elif search_string in volume_attrmap:
        LOG.info("Cannot translate WinVolume object. See "
                 "https://github.com/CybOXProject/python-cybox/issues/269")
        # set_field(volume, volume_attrmap[search_string], content_string, condition)
        # prefetch.volume = volume
    elif search_string == "PrefetchItem/AccessedFileList/AccessedFile":
        s = String(xml.sanitize(content_string))
        s.condition = condition
        prefetch.accessed_file_list = AccessedFileList(s)
    else:
        return None

    return Object(prefetch)

def create_process_obj(search_string, content_string, condition):
    from cybox.common import ExtractedFeatures, ExtractedStrings, ExtractedString
    from cybox.objects.process_object import Process, PortList, ImageInfo
    from cybox.objects.port_object import Port

    proc        = Process()
    port        = Port()
    image       = ImageInfo()
    exfeatures  = ExtractedFeatures()

    proc_attrmap = {
        "ProcessItem/Username": "username",
        "ProcessItem/name": "name",
        "ProcessItem/parentpid": "parent_pid",
        "ProcessItem/pid": "pid",
        "ProcessItem/startTime": "start_time",
        "ProcessItem/userTime": "user_time",
    }

    port_attrmap = {
        "ProcessItem/PortList/PortItem/localPort": "port_value",
        "ProcessItem/PortList/PortItem/remotePort": "port_value",
        "ProcessItem/PortList/PortItem/protocol": "layer4_protcol"
    }

    image_attrmap = {
        "ProcessItem/arguments": "command_line",
        "ProcessItem/path": "path",
        "ServiceItem/path": "path"
    }

    netconn_keys = (
        "ProcessItem/PortList/PortItem/CreationTime",
        "ProcessItem/PortList/PortItem/localIP",
        "ProcessItem/PortList/PortItem/remoteIP"
    )

    winproc_keys = (
        "HandleList",
        "SectionList",
        "ProcessItem/SecurityID",
        "ProcessItem/SecurityType"
    )

    if any(term in search_string for term in winproc_keys):
        return create_win_process_obj(search_string, content_string, condition)
    elif search_string in netconn_keys:
        return create_network_connection_obj(search_string, content_string, condition)
    elif search_string in proc_attrmap:
        set_field(proc, proc_attrmap[search_string], content_string, condition)
    elif search_string in port_attrmap:
        set_field(port, port_attrmap[search_string], content_string, condition)
        proc.port_list = PortList(port)
    elif search_string in image_attrmap:
        set_field(image, image_attrmap[search_string], content_string, condition)
        proc.image_info = image
    elif search_string == "ProcessItem/StringList/string":
        s = ExtractedString()
        set_field(s, "string_value", content_string, condition)
        exfeatures = ExtractedFeatures()
        exfeatures.strings = ExtractedStrings(s)
        proc.extracted_features = exfeatures
    else:
        return None

    return Object(proc)

def create_registry_obj(search_string, content_string, condition):
    from cybox.objects.win_registry_key_object import (
        WinRegistryKey, RegistryValue, RegistryValues
    )

    value = RegistryValue()
    key   = WinRegistryKey()

    key_attrmap = {
        "RegistryItem/Username": "creator_username",
        "RegistryItem/Hive": "hive",
        "RegistryItem/KeyPath": "key",
        "RegistryItem/Modified": "modified_time",
        "RegistryItem/NumSubKeys": "num_subkeys",
        "RegistryItem/NumValues": "num_values",
    }

    value_attrmap = {
        "RegistryItem/Text": "data",
        "RegistryItem/Value": "data",
        "RegistryItem/Type": "data_type",
        "RegistryItem/ValueName": "name"
    }

    if search_string in key_attrmap:
        set_field(key, key_attrmap[search_string], content_string, condition)
    elif search_string in value_attrmap:
        set_field(value, value_attrmap[search_string], content_string, condition)
        key.values = RegistryValues(value)
    elif search_string == "RegistryItem/Path":
        if not content_string.startswith("HKEY_"):
            set_field(key, "key", content_string, condition)
        elif "\\" not in content_string:
            set_field(key, "hive", content_string, condition)
        else:
            hiveval, keyval = content_string.split("\\", 1)
            set_field(key, "hive", hiveval, condition='Equals')
            set_field(key, "key", keyval, condition)
    else:
        return None

    return Object(key)

def create_service_obj(search_string, content_string, condition):
    from cybox.objects.win_service_object import WinService, ServiceDescriptionList
    from cybox.common.hashes import  HashList
    from cybox.common.properties import String

    hashlist = HashList()
    service = WinService()

    attrmap = {
        "ServiceItem/arguments": "startup_command_line",
        "ServiceItem/mode": "startup_type",
        "ServiceItem/name": "service_name",
        "ServiceItem/serviceDLL": "service_dll",
        "ServiceItem/serviceDLLCertificateSubject": "service_dll_certificate_subject",
        "ServiceItem/serviceDLLCertificateIssuer": "service_dll_certificate_issuer",
        "ServiceItem/serviceDLLSignatureExists": "service_dll_signature_exists",
        "ServiceItem/serviceDLLSignatureVerified": "service_dll_signature_verified",
        "ServiceItem/serviceDLLSignatureDescription": "service_dll_signature_description",
        "ServiceItem/startedAs": "started_as",
        "ServiceItem/status": "service_status",
        "ServiceItem/type": "service_type"
    }

    hashmap = {
        "ServiceItem/serviceDLLmd5sum": "md5",
        "ServiceItem/serviceDLLsha1sum": "sha1",
        "ServiceItem/serviceDLLsha256sum": "sha256"
    }

    proc_keys = (
        "ServiceItem/path",
        "ServiceItem/pid"
    )

    if search_string in proc_keys:
        return create_process_obj(search_string, content_string, condition)
    elif search_string in attrmap:
        set_field(service, attrmap[search_string], content_string, condition)
    elif search_string in hashmap:
        set_field(hashlist, hashmap[search_string], content_string, condition)
        service.service_dll_hashes = hashlist
    elif search_string == "ServiceItem/description":
        s = String(xml.sanitize(content_string))
        service.description_list = ServiceDescriptionList(s)
    else:
        return None

    return Object(service)


def create_system_object(search_string, content_string, condition):
    from cybox.objects.address_object import Address
    from cybox.objects.system_object import (
        System, OS, BIOSInfo, NetworkInterface, NetworkInterfaceList,
        DHCPServerList, IPInfo, IPInfoList
    )

    winsys_keys = (
        "SystemInfoItem/productID",
        "SystemInfoItem/regOrg",
        "SystemInfoItem/regOwner",
        "SystemInfoItem/domain"
    )

    sys_attrmap = {
        "SystemInfoItem/processor": "processor",
        "SystemInfoItem/timezoneDST": "timezone_dst",
        "SystemInfoItem/timezoneStandard": "timezone_standard",
        "SystemInfoItem/totalphysical": "total_physical",
        "SystemInfoItem/uptime": "uptime",
        "SystemInfoItem/user": "username",
        "SystemInfoItem/availphysical": "available_physical_memory",
        "SystemInfoItem/date": "date",
        "SystemInfoItem/hostname": "hostname"
    }

    os_attrmap = {
        "SystemInfoItem/buildNumber": "build_number",
        "SystemInfoItem/installDate": "install_date",
        "SystemInfoItem/OS": "platform",
        "SystemInfoItem/patchLevel": "patch_level"
    }

    bios_attrmap = {
        "SystemInfoItem/biosInfo/biosDate": "bios_date",
        "SystemInfoItem/biosInfo/biosVersion": "bios_version"
    }

    iface_attrmap = {
        "SystemInfoItem/MAC": "mac",
        "SystemInfoItem/networkArray/networkInfo/MAC": "mac",
        'SystemInfoItem/networkArray/networkInfo/adapter': "adapter",
        'SystemInfoItem/networkArray/networkInfo/description': "description",
        'SystemInfoItem/networkArray/networkInfo/dhcpLeaseExpires': "dhcp_lease_expires",
        'SystemInfoItem/networkArray/networkInfo/dhcpLeaseObtained': "dhcp_lease_obtained"
    }

    os_ = OS()
    system = System()
    bios = BIOSInfo()
    ipinfo = IPInfo()
    iface = NetworkInterface()

    if search_string in sys_attrmap:
        set_field(system, sys_attrmap[search_string], content_string, condition)
    elif search_string in os_attrmap:
        set_field(os_, os_attrmap[search_string], content_string, condition)
        system.os = os_
    elif search_string in bios_attrmap:
        set_field(bios, bios_attrmap[search_string], content_string, condition)
        system.bios_info = bios
    elif search_string in iface_attrmap:
        set_field(iface, iface_attrmap[search_string], content_string, condition)
        system.network_interface_list = NetworkInterfaceList(iface)
    elif search_string in winsys_keys:
        return create_win_system_obj(search_string, content_string, condition)
    elif search_string == 'SystemInfoItem/networkArray/networkInfo/dhcpServerArray/dhcpServer':
        addr = Address(xml.sanitize(content_string), category=Address.CAT_IPV4)
        iface.dhcp_server_list = DHCPServerList(addr)
        system.network_interface_list = NetworkInterfaceList(iface)
    elif search_string == 'SystemInfoItem/networkArray/networkInfo/ipArray/ipInfo/ipAddress':
        addr = Address(xml.sanitize(content_string), category=Address.CAT_IPV4)
        ipinfo.ip_address = addr
        iface.ip_list = IPInfoList(ipinfo)
        system.network_interface_list = NetworkInterfaceList(iface)
    elif content_string == 'SystemInfoItem/networkArray/networkInfo/ipArray/ipInfo/subnetMask':
        addr = Address(xml.sanitize(content_string), category=Address.CAT_IPV4_NETMASK)
        ipinfo.subnet_mask = addr
        iface.ip_list = IPInfoList(ipinfo)
        system.network_interface_list = NetworkInterfaceList(iface)
    else:
        return None

    return Object(system)


def create_system_restore_obj(search_string, content_string, condition):
    from cybox.objects.win_system_restore_object import WinSystemRestore, HiveList
    from cybox.common.properties import String

    restore = WinSystemRestore()

    attrmap = {
        "SystemRestoreItem/RestorePointName": "restore_point_name",
        "SystemRestoreItem/RestorePointFullPath": "restore_point_full_path",
        "SystemRestoreItem/RestorePointDescription": "restore_point_description",
        "SystemRestoreItem/RestorePointType": "restore_point_type",
        "SystemRestoreItem/Created": "created",
        "SystemRestoreItem/ChangeLogEntrySequenceNumber": "changelog_entry_sequence_number",
        "SystemRestoreItem/ChangeLogEntryFlags": "changelog_entry_flags",
        "SystemRestoreItem/FileAttributes": "file_attributes",
        "SystemRestoreItem/OriginalFileName": "original_file_name",
        "SystemRestoreItem/BackupFileName": "backup_file_name",
        "SystemRestoreItem/AclChangeUsername": "acl_change_sid",
        "SystemRestoreItem/AclChangeSecurityID": "acl_change_security_id",
        "SystemRestoreItem/OriginalShortFileName": "original_short_file_name",
        "SystemRestoreItem/ChangeLogEntryType": "changelog_entry_type"
    }

    if search_string in attrmap:
        set_field(restore, attrmap[search_string], content_string, condition)
    elif content_string == "SystemRestoreItem/RegistryHives/String":
        s = String(xml.sanitize(content_string))
        s.condition = condition
        restore.registry_hive_list = HiveList(s)
    else:
        return None

    return Object(restore)


def create_user_obj(search_string, content_string, condition):
    from cybox.objects.user_account_object import UserAccount
    from cybox.objects.win_user_object import WinGroup, WinGroupList

    user_account = UserAccount()
    group = WinGroup()

    winuser_keys = (
        "UserItem/SecurityID",
        "UserItem/SecurityType",
    )

    account_keys = (
        "UserItem/description",
        "UserItem/disabled",
        "UserItem/lockedout"
    )

    attrmap = {
        "UserItem/fullname": "full_name",
        "UserItem/homedirectory": "home_directory",
        "UserItem/passwordrequired": "password_required",
        "UserItem/scriptpath": "script_path",
        "UserItem/userpasswordage": "user_password_age"
    }

    if search_string in winuser_keys:
        return create_win_user_obj(search_string, content_string, condition)
    elif search_string in account_keys:
        return create_account_obj(search_string, content_string, condition)
    elif search_string in attrmap:
        set_field(user_account, attrmap[search_string], content_string, condition)
    elif search_string == "UserItem/grouplist/groupname":
        set_field(group, "name", content_string, condition)
        user_account.group_list = WinGroupList(group)
    else:
        return None

    return Object(user_account)

def create_volume_obj(search_string, content_string, condition):
    from cybox.objects.volume_object import Volume, FileSystemFlagList
    from cybox.common.properties import String

    attrmap = {
        "VolumeItem/ActualAvailableAllocationUnits": "actual_available_allocation_units",
        "VolumeItem/BytesPerSector": "bytes_per_sector",
        "VolumeItem/CreationTime": "creation_time",
        "VolumeItem/DevicePath": "device_path",
        "VolumeItem/FileSystemType": "file_system_type",
        "VolumeItem/IsMounted": "is_mounted",
        "VolumeItem/Name": "name",
        "VolumeItem/SectorsPerAllocationUnit": "sectors_per_allocation_unit",
        "VolumeItem/SerialNumber": "serial_number",
        "VolumeItem/TotalAllocationUnits": "total_allocation_units"
    }

    volume = Volume()

    if search_string == "VolumeItem/DriveLetter":
        return create_win_volume_obj(search_string, content_string, condition)
    elif search_string in attrmap:
        set_field(volume, attrmap[search_string], content_string, condition)
    elif search_string == "VolumeItem/FileSystemFlags":
        s = String(xml.sanitize(content_string))
        s.condition = condition
        volume.file_system_flag_list = FileSystemFlagList(s)
    else:
        return None

    return Object(volume)


def create_win_system_obj(search_string, content_string, condition):
    from cybox.objects.win_system_object import WinSystem

    attrmap = {
        'SystemInfoItem/domain': "domain",
        'SystemInfoItem/productID': "product_id",
        'SystemInfoItem/productName': "product_name",
        'SystemInfoItem/regOrg': "registered_organization",
        'SystemInfoItem/regOwner': "registered_owner"
    }

    if search_string not in attrmap:
        return None

    winsys = WinSystem()
    set_field(winsys, attrmap[search_string], content_string, condition)

    return Object(winsys)

def create_win_task_obj(search_string, content_string, condition):
    from cybox.objects.win_task_object import (
        WinTask, TaskAction, TaskActionList, IComHandlerAction,
        IExecAction, Trigger, TriggerList, IShowMessageAction
    )

    attrmap = {
        "TaskItem/AccountLogonType": "account_logon_type",
        "TaskItem/AccountName": "account_name",
        "TaskItem/AccountRunLevel": "account_run_level",
        "TaskItem/ApplicationName": "application_name",
        "TaskItem/Comment": "comment",
        "TaskItem/CreationDate": "creation_date",
        "TaskItem/Creator": "creator",
        "TaskItem/ExitCode": "exit_code",
        "TaskItem/MaxRunTime": "max_run_time",
        "TaskItem/MostRecentRunTime": "most_recent_run_time",
        "TaskItem/Name": "name",
        "TaskItem/NextRunTime": "next_run_time",
        "TaskItem/Parameters": "parameters",
        "TaskItem/WorkItemData": "work_item_data",
        "TaskItem/WorkingDirectory": "working_directory",
        "TaskItem/Flag": "flags",
        "TaskItem/Priority": "priority",
        "TaskItem/Status": "status"
    }

    icom_attrmap = {
        "TaskItem/ActionList/Action/COMClassId": "com_class_id",
        "TaskItem/ActionList/Action/COMData": "com_data"
    }

    iexecaction_attrmap = {
        "TaskItem/ActionList/Action/ExecArguments": "exec_arguments",
        "TaskItem/ActionList/Action/ExecProgramPath": "exec_program_path",
        "TaskItem/ActionList/Action/ExecWorkingDirectory": "exec_working_directory"
    }

    ishowmessage_attrmap = {
        "TaskItem/ActionList/Action/ShowMessageBody": "show_message_body",
        "TaskItem/ActionList/Action/ShowMessageTitle": "show_message_title"
    }

    trigger_attrmap = {
        "TaskItem/TriggerList/Trigger/TriggerBegin": "trigger_begin",
        "TaskItem/TriggerList/Trigger/TriggerDelay": "trigger_delay",
        "TaskItem/TriggerList/Trigger/TriggerEnd": "trigger_end",
        "TaskItem/TriggerList/Trigger/TriggerFrequency": "trigger_frequency",
        "TaskItem/TriggerList/Trigger/TriggerMaxRunTime": "trigger_max_run_time",
        "TaskItem/TriggerList/Trigger/TriggerSessionChangeType": "trigger_session_change_type"
    }

    email_map = {
        "TaskItem/ActionList/Action/EmailBCC": "Email/BCC",
        "TaskItem/ActionList/Action/EmailBody": "Email/Body",
        "TaskItem/ActionList/Action/EmailCC": "Email/CC",
        "TaskItem/ActionList/Action/EmailSubject": "Email/Subject",
        "TaskItem/ActionList/Action/EmailFrom": "Email/From",
        "TaskItem/ActionList/Action/EmailTo": "Email/To",
        "TaskItem/ActionList/Action/EmailReplyTo": "Email/ReplyTo",
        "TaskItem/ActionList/Action/EmailServer": "Email/EmailServer"
    }

    task     = WinTask()
    action   = TaskAction()
    actions  = TaskActionList(action)
    trigger  = Trigger()
    triggers = TriggerList(trigger)

    if search_string in attrmap:
        set_field(task, attrmap[search_string], content_string, condition)
    elif search_string in icom_attrmap:
        handler = IComHandlerAction()
        set_field(handler, icom_attrmap[search_string], content_string, condition)
        action.icomhandleraction = handler
        task.action_list = actions
    elif search_string in email_map:
        email = create_email_obj(email_map[search_string], content_string, condition)
        action.iemailaction = email
        task.action_list = actions
    elif search_string in iexecaction_attrmap:
        execaction = IExecAction()
        set_field(execaction, iexecaction_attrmap[search_string], content_string, condition)
        action.iexecaction = execaction
        task.action_list = actions
    elif search_string in ishowmessage_attrmap:
        ishowmessage = IShowMessageAction()
        set_field(ishowmessage, ishowmessage_attrmap[search_string], content_string, condition)
        action.ishowmessageaction = ishowmessage,
        task.action_list = actions
    elif search_string in trigger_attrmap:
        set_field(trigger, trigger_attrmap[search_string], content_string, condition)
        task.trigger_list = triggers
    elif search_string == "TaskItem/ActionList/Action/ActionType":
        set_field(action, "action_type", content_string, condition)
        task.action_list = actions
    else:
        return None

    return Object(task)


def create_win_volume_obj(search_string, content_string, condition):
    LOG.info("Cannot translate WinVolume object. See "
             "https://github.com/CybOXProject/python-cybox/issues/269")

    return None
    # from cybox.objects.win_volume_object import WinVolume
    #
    # if search_string != "VolumeItem/DriveLetter":
    #     return None
    #
    # volume = WinVolume()
    # set_field(volume, "drive_letter", content_string, condition)
    #
    # return Object(volume)


def create_unix_file_obj(search_string, content_string, condition):
    # python-cybox 2.1.0.11 does not support Unix File Object
    pass


def create_win_file_obj(search_string, content_string, condition):
    from cybox.objects.win_file_object import (
        WinFile, WindowsFileAttribute, WindowsFileAttributes, Stream, StreamList
    )

    attrmap = {
        "FileItem/Drive": "drive",
        "FileItem/FilenameAccessed": "filename_accessed_time",
        "FileItem/FilenameCreated": "filename_created_time",
        "FileItem/FilenameModified": "filename_modified_time",
        "FileItem/SecurityID": "security_id",
        "FileItem/SecurityType": "security_type",
        "FileItem/StreamList/Stream/Md5sum": "md5",
        "FileItem/StreamList/Stream/Sha1sum": "sha1",
        "FileItem/StreamList/Stream/Sha256sum": "sha256"
    }

    stream_attrmap = {
        "FileItem/StreamList/Stream/Name": "name",
        "FileItem/StreamList/Stream/SizeInBytes": "size_in_bytes"
    }

    file_ = WinFile()
    stream = Stream()
    streams = StreamList(stream)

    if search_string in attrmap:
        set_field(file_, attrmap[search_string], content_string, condition)
    if search_string in stream_attrmap:
        set_field(stream, stream_attrmap[search_string], content_string, condition)
        file_.stream_list = streams
    elif search_string == "FileItem/FileAttributes":
        attr = WindowsFileAttribute(content_string)
        attr.condition = condition
        file_.file_attributes_list = WindowsFileAttributes(attr)
    else:
        return None

    return Object(file_)

def create_pefile_obj(search_string, content_string, condition):
    from cybox.common import DigitalSignature
    from cybox.objects.file_object import (
        EPJumpCode, EntryPointSignature, EntryPointSignatureList,
        Packer, PackerList
    )
    from cybox.objects.win_executable_file_object import (
        WinExecutableFile, PEVersionInfoResource, PEResource, PEResourceList,
        PEChecksum, PEHeaders, PEOptionalHeader, PEExports, PEExportedFunctions,
        PEExportedFunction, PEImport, PEImportedFunction, PEImportedFunctions,
        PEImportList, PEFileHeader, PESection, PESectionList, PESectionHeaderStruct
    )

    ds_attrmap = {
        "/PEInfo/DigitalSignature/CertificateIssuer": "certificate_issuer",
        "/PEInfo/DigitalSignature/CertificateSubject": "certificate_subject",
        "/PEInfo/DigitalSignature/Description": "certificate_description",
        "/PEInfo/DigitalSignature/SignatureExists": "signature_exists",
        "/PEInfo/DigitalSignature/SignatureVerified": "signature_verified"
    }

    verinfo_attrmap = {
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/Comments": "comments",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/CompanyName": "companyname",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileDescription": "filedescription",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileVersion": "fileversion",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/InternalName": "internalname",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/Language": "language",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/LegalCopyright": "legalcopyright",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/LegalTrademarks": "legaltrademarks",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/OriginalFilename": "originalfilename",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/PrivateBuild": "privatebuild",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/ProductName": "productname",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/ProductVersion": "productversion",
        "FileItem/PEInfo/VersionInfoList/VersionInfoItem/SpecialBuild": "specialbuild"
    }

    resource_attrmap = {
        "FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Name": "name",
        "FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Type": "type_"
    }

    checksum_attrmap = {
        "/PEInfo/PEChecksum/PEComputedAPI": "pe_computed_api",
        "/PEInfo/PEChecksum/PEFileAPI": "pe_file_api",
        "/PEInfo/PEChecksum/PEFileRaw": "pe_file_raw"
    }

    epsig_attrmap = {
        "/PEInfo/DetectedEntryPointSignature/Name": "name",
        "/PEInfo/DetectedEntryPointSignature/Type": "type_",
    }

    jmpcode_attrmap = {
        "/PEInfo/EpJumpCodes/Depth": "depth",
        "/PEInfo/EpJumpCodes/Opcodes": "opcodes"
    }

    exports_attrmap = {
        "/PEInfo/Exports/ExportsTimeStamp": "exports_time_stamp",
        "/PEInfo/Exports/NumberOfNames": "number_of_names"
    }

    winexec = WinExecutableFile()
    ds = DigitalSignature()
    verinfo = PEVersionInfoResource()
    verinforesources = PEResourceList(verinfo)
    resource = PEResource()
    resources = PEResourceList(resource)
    checksum = PEChecksum()
    exports = PEExports()

    if "/PEInfo/ExtraneousBytes" in search_string:
        set_field(winexec, "extraneous_bytes", content_string, condition)
    elif any(k in search_string for k in ds_attrmap):
        attr = utils.partial_match(ds_attrmap, search_string)
        set_field(ds, attr, content_string, condition)
        winexec.digital_signature = ds
    elif any(k in search_string for k in checksum_attrmap):
        attr = utils.partial_match(checksum_attrmap, search_string)
        set_field(checksum, attr, content_string, condition)
        winexec.pe_checksum = checksum
    elif any(k in search_string for k in exports_attrmap):
        attr = utils.partial_match(exports_attrmap, search_string)
        set_field(exports, attr, content_string, condition)
        winexec.exports = exports
    elif any(k in search_string for k in epsig_attrmap):
        packer = Packer()
        epsig = EntryPointSignature()
        packerlist = PackerList(packer)
        epsiglist = EntryPointSignatureList(epsig)
        packer.detected_entrypoint_signatures = epsiglist
        winexec.packer_list = packerlist
        attr = utils.partial_match(epsig_attrmap, search_string)
        set_field(epsig, attr, content_string, condition)
    elif any(k in search_string for k in jmpcode_attrmap):
        epjumpcode = EPJumpCode()
        packer = Packer()
        packerlist = PackerList(packer)
        packer.ep_jump_codes = epjumpcode
        winexec.packer_list = packerlist
        attr = utils.partial_match(jmpcode_attrmap, search_string)
        set_field(epjumpcode, attr, content_string, condition)
    elif search_string in verinfo_attrmap:
        set_field(verinfo, verinfo_attrmap[search_string], content_string, condition)
        winexec.resources = verinforesources
    elif search_string in resource_attrmap:
        set_field(resource, resource_attrmap[search_string], content_string, condition)
        winexec.resources = resources
    elif "/PEInfo/BaseAddress" in search_string:
        headers = PEHeaders()
        opt = PEOptionalHeader()
        set_field(opt, "base_of_code", content_string, condition)
        headers.optional_header = opt
        winexec.headers = headers
    elif "/Exports/ExportedFunctions/string" in search_string:
        func = PEExportedFunction()
        funclist = PEExportedFunctions(func)
        exports.exported_functions = funclist
        winexec.exports = exports
        set_field(func, "function_name", content_string, condition)
    elif search_string in ["FileItem/PEInfo/ImportedModules/Module/ImportedFunctions/string",
                           "DriverItem/PEInfo/ImportedModules/Module/ImportedFunctions/string"]:
        import_ = PEImport()
        imports = PEImportList(import_)
        func = PEImportedFunction()
        funcs = PEImportedFunctions(func)
        import_.imported_functions = funcs
        winexec.imports = imports
        set_field(func, "function_name", content_string, condition)
    elif "/PEInfo/ImportedModules/Module/Name" in search_string:
        import_ = PEImport()
        imports = PEImportList(import_)
        winexec.imports = imports
        set_field(import_, "file_name", content_string, condition)
    elif "/PEInfo/PETimeStamp" in search_string:
        header = PEFileHeader()
        headers = PEHeaders()
        headers.file_header = header
        winexec.headers = headers
        set_field(header, "time_date_stamp", content_string, condition)
    elif "/PEInfo/Sections/Section/DetectedCharacteristics" in search_string:
        section = PESection()
        sections = PESectionList(section)
        header  = PESectionHeaderStruct()
        section.section_header = header
        winexec.sections = sections
        set_field(header, "characteristics", content_string, condition)
    else:
        return None

    return Object(winexec)

def create_win_user_obj(search_string, content_string, condition):
    from cybox.objects.win_user_object import WinUser

    winuser = WinUser()

    attrmap = {
        "UserItem/SecurityID": "security_id",
        "UserItem/SecurityType": "security_type"
    }

    if search_string in attrmap:
        set_field(winuser, attrmap[search_string], content_string, condition)
    else:
        return None

    return Object(winuser)

def create_account_obj(search_string, content_string, condition):
    from cybox.objects.account_object import Account

    account = Account()

    attrmap = {
        "UserItem/description": "description",
        "UserItem/disabled": "disabled",
        "UserItem/lockedout": "locked_out"
    }

    if search_string in attrmap:
        set_field(account, attrmap[search_string], content_string, condition)
    else:
        return None

    return Object(account)


def create_win_memory_page_obj(search_string, content_string, condition):
    from cybox.objects.win_memory_page_region_object import WinMemoryPageRegion

    if search_string != "ProcessItem/SectionList/MemorySection/Protection":
        return

    page = WinMemoryPageRegion()
    set_field(page, "protect", content_string, condition)

    return Object(page)


def create_win_process_obj(search_string, content_string, condition):
    from cybox.objects import win_process_object
    from cybox.common import hashes

    proc = win_process_object.WinProcess()

    handle_attrmap = {
        "ProcessItem/HandleList/Handle/AccessMask": "access_mask",
        "ProcessItem/HandleList/Handle/Index": "id_",
        "ProcessItem/HandleList/Handle/Name": "name",
        "ProcessItem/HandleList/Handle/ObjectAddress": "object_address",
        "ProcessItem/HandleList/Handle/PointerCount": "pointer_count",
        "ProcessItem/HandleList/Handle/Type": "type_",
    }

    memory_attrmap = {
        "ProcessItem/SectionList/MemorySection/Injected": "is_injected",
        "ProcessItem/SectionList/MemorySection/Mapped": "is_mapped",
        "ProcessItem/SectionList/MemorySection/Name": "name",
        "ProcessItem/SectionList/MemorySection/RegionSize": "region_size",
        "ProcessItem/SectionList/MemorySection/RegionStart": "region_start",
    }

    hash_attrmap = {
        "ProcessItem/SectionList/MemorySection/Md5sum": "md5",
        "ProcessItem/SectionList/MemorySection/Sha1Sum": "sha1",
        "ProcessItem/SectionList/MemorySection/Sha256Sum": "sha256",
    }

    proc_attrmap = {
        "ProcessItem/SecurityID": "security_id",
        "ProcessItem/SecurityType": "security_type"
    }

    if "/PEInfo" in search_string:
        return create_pefile_obj(search_string, content_string, condition)
    elif search_string == "ProcessItem/SectionList/MemorySection/Protection":
        create_win_memory_page_obj(search_string, content_string, condition)
    elif search_string in proc_attrmap:
        set_field(proc, proc_attrmap[search_string], content_string, condition)
    elif search_string in handle_attrmap:
        handle = win_process_object.WinHandle()
        handles = win_process_object.WinHandleList(handle)
        proc.handle_list = handles
        set_field(handle, handle_attrmap[search_string], content_string, condition)
    elif search_string in memory_attrmap:
        section = win_process_object.Memory()
        sections = win_process_object.MemorySectionList(section)
        proc.section_list = sections
        set_field(section, memory_attrmap[search_string], content_string, condition)
    elif search_string in hash_attrmap:
        hashlist = hashes.HashList()
        section = win_process_object.Memory()
        section.hashes = hashlist
        sections = win_process_object.MemorySectionList(section)
        proc.section_list = sections
        set_field(hashlist, hash_attrmap[search_string], content_string, condition)
    else:
        return None

    return Object(proc)


def make_object(search_string, content_string, condition):
    retval  = None
    key     = search_string.split('/', 1)[0]

    if key in OBJECT_FUNCS:
        makefunc = OBJECT_FUNCS[key]
        retval   = makefunc(search_string, content_string, condition)

    if retval is None:
        LOG.debug("Unable to map %s to CybOX Object.", search_string)

    return retval


OBJECT_FUNCS = {
    'DiskItem': create_disk_obj,
    'DnsEntryItem': create_dns_obj,
    'DriverItem': create_driver_obj,
    'Email': create_email_obj,
    'EventLogItem': create_win_event_log_obj,
    'FileItem': create_file_obj,
    'HookItem': create_hook_obj,
    'ModuleItem': create_library_obj ,
    'Network': create_network_connection_obj,
    'PortItem': create_port_obj,
    'PrefetchItem': create_prefetch_obj,
    'ProcessItem': create_process_obj,
    'RegistryItem': create_registry_obj,
    'RouteEntryItem': create_net_route_obj,
    'ServiceItem': create_service_obj,
    'SystemInfoItem': create_system_object,
    'SystemRestoreItem': create_system_restore_obj,
    'TaskItem': create_win_task_obj,
    'UserItem': create_user_obj,
    'VolumeItem': create_volume_obj
}
