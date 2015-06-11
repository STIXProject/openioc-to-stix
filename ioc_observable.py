# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import uuid
import logging
import collections

# external utilities
import cybox
from cybox import utils
from cybox.common.properties import String

# external cybox bindings
import cybox.bindings.cybox_core as core
import cybox.bindings.cybox_common as common
import cybox.bindings.account_object as accountobj
import cybox.bindings.address_object as addressobj
import cybox.bindings.disk_object as diskobj
import cybox.bindings.disk_partition_object as diskpartitionobj
import cybox.bindings.dns_record_object as dnsrecordobj
import cybox.bindings.dns_cache_object as dnscacheobj
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


from cybox.common.properties import _LongBase, _IntegerBase, _FloatBase

# Used in set_field() method
NUMERIC_FIELD_BASES = (_FloatBase, _IntegerBase, _LongBase)

# Module logger
LOG = logging.getLogger(__name__)


def is_numeric(obj, attrname):
    klass = obj.__class__

    field = getattr(klass, attrname)
    field_type = field.type_

    if not field_type:
        return False

    return any(issubclass(field_type, base) for base in NUMERIC_FIELD_BASES)


def sanitize(string):
    chars = ('<', '>', "'", '"', '&')

    if not isinstance(string, basestring):
        return string

    # Remove CDATA wrapper if it existed.
    string = utils.unwrap_cdata(string)

    if any(c in string for c in chars):
        return utils.wrap_cdata(string)
    else:
        return string


def create_object(search_string, content_string, condition):
    retval  = None
    key     = search_string.split('/', 1)[0]

    if key in OBJECT_FUNCS:
        # Get the object creation function for the key
        makefunc = OBJECT_FUNCS[key]
        retval   = makefunc(search_string, content_string, condition)

    if retval is None:
        LOG.debug("Unable to map %s to CybOX Object.", search_string)

    return retval


def _assert_field(obj, attrname):
    klass = obj.__class__

    if hasattr(obj, attrname):
        return

    if hasattr(klass, attrname):
       return

    raise AttributeError("Object has no attribute: %s" % attrname)

def _set_field(obj, attrname, value, condition=None):

    # Set the attribute
    setattr(obj, attrname, sanitize(value))

    attr = getattr(obj, attrname)

    if condition:
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

    if is_numeric(obj, attrname):
        return _set_numeric_field(obj, attrname, value, condition)
    else:
        return _set_field(obj, attrname, value, condition)


def has_content(object):
    if not hasattr(object, '_fields'):
        return False

    return any(x for x in object._fields.itervalues())


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
        "DiskItem/PartitionList/Partition/PartitionNumber": "partition_number",
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

    return disk

def create_dns_obj(search_string, content_string, condition):
    from cybox.objects.dns_record_object import DNSRecord
    from cybox.objects.dns_cache_object import DNSCache, DNSCacheEntry

    cache = DNSCache()
    record = DNSRecord()

    attrmap = {
        "DnsEntryItem/DataLength": "data_length",
        "DnsEntryItem/Flags": "flags",
        "DnsEntryItem/Host": "domain_name",
        "RecordData/Host": "record_data",
        "RecordData/IPv4Address": "record_data",
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

    return cache

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
        return createWinExecObj(search_string, content_string, condition)
    if search_string in file_keys:
        return createFileObj(search_string, content_string, condition)
    elif search_string in device_attrmap:
        set_field(device, device_attrmap[search_string], content_string, condition)
        windriver.device_object_list = DeviceObjectList(device)
    elif search_string in driver_attrmap:
        set_field(windriver, driver_attrmap[search_string], content_string, condition)
    else:
        return None

    return windriver

def create_email_obj(search_string, content_string, condition):
    from cybox.objects.file_object import File
    from cybox.objects.email_message_object import (
        Attachments, EmailMessage, EmailHeader, ReceivedLine, ReceivedLineList
    )

    email       = EmailMessage()
    header      = EmailHeader()
    received    = ReceivedLine()
    attachment  = File()

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

    if has_content(attachment):
        return [email, attachment]

    return email


def create_win_event_log_obj(search_string, content_string, condition):
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
        "EventLogItem/type": "type",
        "EventLogItem/user": "user",
        "EventLogItem/writeTime": "write_time"
    }

    if search_string in attrmap:
        set_field(eventlog, attrmap[search_string], content_string, condition)
    elif search_string == "EventLogItem/unformattedMessage/string":
        s = String(sanitize(content_string))
        s.condition = condition
        eventlog.unformatted_message_list = UnformattedMessageList(s)
    else:
        return None

    return eventlog

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
        return createWinFileObj(search_string, content_string, condition)
    elif search_string == "FileItem/INode":
        return createUnixFileObj(search_string, content_string, condition)
    elif '/PEInfo/' in search_string:
        return createWinExecObj(search_string, content_string, condition)
    elif search_string in ("FileItem/StringList/string", "DriverItem/StringList/string"):
        extracted_features = ExtractedFeatures()
        extracted_features.strings = ExtractedStrings(sanitize(content_string))
        f.extracted_features = extracted_features
    else:
        return None

    return f

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

    return hook

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

    return library


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
        "ProcessItem/PortList/PortItem/localIP": ("ip_address", "source_socket_address"),
        "PortItem/localPort": ("port", "source_port"),
        "PortItem/remotePort": ("port", "destination_port")
    }

    if search_string in socket_attrmap:
        socket_field, net_field = socket_attrmap[search_string]
        set_field(socketaddr, socket_field, content_string, condition)
        set_field(net, net_field, socketaddr)
    elif search_string == "Network/DNS":
        host = HostField()
        header_fields.host = host
        header.parsed_header = header_fields
        set_field(host, "domain", content_string, condition)
    elif search_string == "Network/HTTP_Referer":
        set_field(header_fields, "referer", content_string, condition)
        header.parsed_header = header_fields
    elif search_string == "Network/String":
        set_field(header, "raw_header", content_string, condition)
    elif search_string == "Network/URI":
        set_field(request_line, "value", content_string, condition)
        request.http_request_line = request
    elif search_string == "Network/UserAgent":
        set_field(header_fields, "user_agent", content_string, condition)
        header.parsed_header = header_fields
    elif"PortItem/CreationTime" in search_string:
        set_field(net, "creation_time", content_string, condition)
    else:
        return None

    return net
    
def create_net_route_obj(search_string, content_string, condition):
    from cybox.objects.network_route_entry_object import NetworkRouteEntry
    from cybox.objects.address_object import Address

    net  = NetworkRouteEntry()
    addr = Address(category=Address.CAT_IPV4)

    addr_keys = {
        "RouteEntryItem/Destination",
        "RouteEntryItem/Gateway",
        "RouteEntryItem/Netmask"
    }

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

    return net


def create_port_obj(search_string, content_string, condition):
    from cybox.objects.port_object import Port

    port = Port()

    netconn_keys = (
        "PortItem/CreationTime",
        "PortItem/localIP",
        "PortItem/remoteIP"
        "PortItem/localPort",
        "PortItem/remotePort",
    )

    if search_string in netconn_keys:
        return create_network_connection_obj(search_string, content_string, condition)
    elif search_string == "PortItem/protocol":
        set_field(port, "protocol", content_string, condition)
    else:
        return None

    return port

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
    volume = WinVolume()

    if search_string in prefected_attrmap:
        set_field(prefetch, prefected_attrmap[search_string], content_string, condition)
    elif search_string in volume_attrmap:
        set_field(volume, volume_attrmap[search_string], content_string, condition)
        prefetch.volume = volume
    elif search_string == "PrefetchItem/AccessedFileList/AccessedFile":
        s = String(sanitize(content_string))
        s.condition = condition
        prefetch.accessed_file_list = AccessedFileList(s)
    else:
        return None

    return prefetch

def create_process_obj(search_string, content_string, condition):
    from cybox.common import ExtractedFeatures, ExtractedString, ExtractedStrings
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
        set_field(exfeatures, "string_value", content_string, condition)
        exfeatures = ExtractedFeatures()
        exfeatures.strings = ExtractedStrings(s)
        proc.extracted_features = exfeatures
    else:
        return None

    return proc

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
            hive, key = content_string.split("\\", 1)
            set_field(key, "hive", hive, condition='Equals')
            set_field(key, "key", key, condition)
    else:
        return None

    return key

def create_service_obj(search_string, content_string, condition):
    from cybox.objects.win_service_object import WinService, ServiceDescriptionList
    from cybox.common.hashes import  HashList

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
        s = String(sanitize(content_string))
        service.description_list = ServiceDescriptionList(s)
    else:
        return None

    return service


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
        addr = Address(sanitize(content_string), category=Address.CAT_IPV4)
        iface.dhcp_server_list = DHCPServerList(addr)
        system.network_interface_list = NetworkInterfaceList(iface)
    elif search_string == 'SystemInfoItem/networkArray/networkInfo/ipArray/ipInfo/ipAddress':
        addr = Address(sanitize(content_string), category=Address.CAT_IPV4)
        ipinfo.ip_address = addr
        iface.ip_list = IPInfoList(ipinfo)
        system.network_interface_list = NetworkInterfaceList(iface)
    elif content_string == 'SystemInfoItem/networkArray/networkInfo/ipArray/ipInfo/subnetMask':
        addr = Address(sanitize(content_string), category=Address.CAT_IPV4_NETMASK)
        ipinfo.subnet_mask = addr
        iface.ip_list = IPInfoList(ipinfo)
        system.network_interface_list = NetworkInterfaceList(iface)
    else:
        return None

    return system


def create_system_restore_obj(search_string, content_string, condition):
    from cybox.objects.win_system_restore_object import WinSystemRestore, HiveList

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
        s = String(sanitize(content_string))
        s.condition = condition
        restore.registry_hive_list = HiveList(s)
    else:
        return None

    return restore


def create_user_obj(search_string, content_string, condition):
    from cybox.objects.user_account_object import UserAccount, GroupList
    from cybox.objects.win_user_object import WinGroup

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
        user_account.group_list = GroupList(group)
    else:
        return None
            
    return user_account

def create_volume_obj(search_string, content_string, condition):
    from cybox.objects.volume_object import Volume, FileSystemFlagList

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
        s = String(sanitize(content_string))
        s.condition = condition
        volume.file_system_flag_list = FileSystemFlagList(s)
    else:
        return None

    return volume


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

    return winsys

def createWinTaskObject(search_string, content_string, condition):
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

    return task


def create_win_volume_obj(search_string, content_string, condition):
    from cybox.objects.win_volume_object import WinVolume

    if search_string != "VolumeItem/DriveLetter":
        return None

    volume = WinVolume()
    set_field(volume, "drive_letter", content_string, condition)

    return volume


def create_unix_file_obj(search_string, content_string, condition):
    # python-cybox 2.1.0.11 does not support Unix File Object
    pass


def createWinFileObj(search_string, content_string, condition):
    #Create the windows file object
    fileobj = winfileobj.WindowsFileObjectType()

    #Assume the IOC indicator value can be mapped to a CybOx type
    valueset = True
        
    if search_string == "FileItem/Drive": 
        fileobj.set_Drive(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
    elif search_string == "FileItem/FileAttributes":
        fileattlist = winfileobj.WindowsFileAttributesType()
        fileatt = winfileobj.WindowsFileAttributeType()
        fileatt.set_valueOf_(sanitize(content_string))
        fileattlist.add_Attribute(fileatt)
        fileobj.set_File_Attributes_List(fileattlist)
    elif search_string == "FileItem/FilenameAccessed": 
        fileobj.set_Filename_Accessed_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "FileItem/FilenameCreated": 
        fileobj.set_Filename_Created_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "FileItem/FilenameModified": 
        fileobj.set_Filename_Modified_Time(common.DateTimeObjectPropertyType(datatype=None, condition=condition, valueOf_=content_string))
    elif search_string == "FileItem/SecurityID":
        fileobj.set_Security_ID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
    elif search_string == "FileItem/SecurityType":
        fileobj.set_Security_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
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
        stream.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
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

    if valueset and fileobj.hasContent_():
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
        epsig.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        epsiglist.add_Entry_Point_Signature(epsig)
        packer.set_Detected_Entrypoint_Signatures(epsiglist)
        packerlist.add_Packer(packer)
        winexecobj.set_Packer_List(packerlist)
    elif search_string == "FileItem/PEInfo/DetectedEntryPointSignature/Type" or search_string == "DriverItem/PEInfo/DetectedEntryPointSignature/Type":
        packerlist = fileobj.PackerListType()
        packer = fileobj.PackerType()
        epsiglist = fileobj.EntryPointSignatureListType()
        epsig = fileobj.EntryPointSignatureType()
        epsig.set_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        epsiglist.add_Entry_Point_Signature(epsig)
        packer.set_Detected_Entrypoint_Signatures(epsiglist)
        packerlist.add_Packer(packer)
        winexecobj.set_Packer_List(packerlist)
    elif search_string == "FileItem/PEInfo/DigitalSignature/CertificateIssuer" or search_string == "DriverItem/PEInfo/DigitalSignature/CertificateIssuer":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Certificate_Issuer(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        winexecobj.set_Digital_Signature(digital_signature)
    elif search_string == "FileItem/PEInfo/DigitalSignature/CertificateSubject" or search_string == "DriverItem/PEInfo/DigitalSignature/CertificateSubject":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Certificate_Subject(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        winexecobj.set_Digital_Signature(digital_signature)
    elif search_string == "FileItem/PEInfo/DigitalSignature/Description" or search_string == "DriverItem/PEInfo/DigitalSignature/Description":
        digital_signature = common.DigitalSignatureInfoType()
        digital_signature.set_Signature_Description(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
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
        epjumpcode.set_Opcodes(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        packer.set_EP_Jump_Codes(epjumpcode)
        packerlist.add_Packer(packer)
        winexecobj.set_Packer_List(packerlist)
    elif search_string == "FileItem/PEInfo/Exports/DllName":
        valueset = False
    elif search_string == "FileItem/PEInfo/Exports/ExportedFunctions/string" or search_string == "DriverItem/PEInfo/Exports/ExportedFunctions/string":
        exports = winexecutablefileobj.PEExportsType()
        exportfunlist = winexecutablefileobj.PEExportedFunctionsType()
        exportfun = winexecutablefileobj.PEExportedFunctionType()
        exportfun.set_Function_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
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
        importfun.set_Function_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        importfunlist.add_Imported_Function(importfun)
        peimport.set_Imported_Functions(importfunlist)
        imports.add_Import(peimport)
        winexecobj.set_Imports(imports)
    elif search_string == "FileItem/PEInfo/ImportedModules/Module/Name" or search_string == "DriverItem/PEInfo/ImportedModules/Module/Name":
        imports = winexecutablefileobj.PEImportListType()
        peimport = winexecutablefileobj.PEImportType()
        peimport.set_File_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
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
        res.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(res)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Size":
        valueset = False
    elif search_string == "FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Type":
        reslist = winexecutablefileobj.PEResourceListType()
        res = winexecutablefileobj.PEResourceType()
        res.set_Type(sanitize(content_string))
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
        sechdr.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        sec.set_Section_Header(sechdr)
        seclist.add_Section(sec)
        winexecobj.set_Sections(seclist)
    elif search_string == "FileItem/PEInfo/Sections/Section/SizeInBytes":
        valueset = False
    elif search_string == "FileItem/PEInfo/Sections/Section/Type" or search_string == "DriverItem/PEInfo/Sections/Section/Type":
        seclist = winexecutablefileobj.PESectionListType()
        sec = winexecutablefileobj.PESectionType()
        sec.set_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
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
        petype.set_valueOf_(sanitize(content_string))
        petype.set_datatype('string')
        winexecobj.set_Type(petype)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/Comments":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_Comments(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/CompanyName":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_CompanyName(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileDescription":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_FileDescription(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileVersion":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_FileVersion(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/InternalName":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_InternalName(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/Language":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_LangID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/LegalCopyright":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_LegalCopyright(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/LegalTrademarks":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_LegalTrademarks(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/OriginalFilename":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_OriginalFilename(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/PrivateBuild":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_PrivateBuild(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/ProductName":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_ProductName(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/ProductVersion":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_ProductVersion(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)
    elif search_string == "FileItem/PEInfo/VersionInfoList/VersionInfoItem/SpecialBuild":
        reslist = winexecutablefileobj.PEResourceListType()
        verres = winexecutablefileobj.PEVersionInfoResourceType()
        verres.set_SpecialBuild(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
        reslist.add_Resource(verres)
        winexecobj.set_Resources(reslist)

    if valueset and winexecobj.hasContent_():
        winexecobj.set_xsi_type('WinExecutableFileObj:WindowsExecutableFileObjectType')
    elif not valueset:
        winexecobj = None
    
    return winexecobj

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

    return winuser

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
    
    return account
 
def create_win_memory_page_obj(search_string, content_string, condition):
    from cybox.objects.win_memory_page_region_object import WinMemoryPageRegion

    if search_string != "ProcessItem/SectionList/MemorySection/Protection":
        return

    page = WinMemoryPageRegion()
    set_field(page, "protect", content_string, condition)

    return page


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
        handle.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
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
        handle.set_Type(common.StringObjectPropertyType(datatype='string', condition=condition, valueOf_=sanitize(content_string)))
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
        memory_section.set_Name(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
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
        winprocobj.set_Security_ID(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))
    elif search_string == "ProcessItem/SecurityType":
        winprocobj.set_Security_Type(common.StringObjectPropertyType(datatype=None, condition=condition, valueOf_=sanitize(content_string)))

    if valueset and winprocobj.hasContent_():
        winprocobj.set_xsi_type('WinProcessObj:WindowsProcessObjectType')
    elif not valueset:
        winprocobj = None

    return winprocobj


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
    'RegistryItem': createRegObj,
    'RouteEntryItem': create_net_route_obj,
    'ServiceItem': createServiceObj,
    'SystemInfoItem': createSystemObj,
    'SystemRestoreItem': createSystemRestoreObj,
    'TaskItem':createWinTaskObject,
    'UserItem': createUserObj,
    'VolumeItem': createVolumeObj
}

#Set the correct attributes for any range values


#Encase any strings with XML escape characters in the proper tags
