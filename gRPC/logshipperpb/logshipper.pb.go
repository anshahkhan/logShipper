// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v6.31.1
// source: logshipper.proto

package __

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type LogRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	OrgId         string                 `protobuf:"bytes,1,opt,name=org_id,json=orgId,proto3" json:"org_id,omitempty"`
	AgentIp       string                 `protobuf:"bytes,2,opt,name=agent_ip,json=agentIp,proto3" json:"agent_ip,omitempty"`
	Hostname      string                 `protobuf:"bytes,3,opt,name=hostname,proto3" json:"hostname,omitempty"`
	EventId       string                 `protobuf:"bytes,4,opt,name=event_id,json=eventId,proto3" json:"event_id,omitempty"`
	LogName       string                 `protobuf:"bytes,5,opt,name=log_name,json=logName,proto3" json:"log_name,omitempty"`
	Source        string                 `protobuf:"bytes,6,opt,name=source,proto3" json:"source,omitempty"`
	Level         string                 `protobuf:"bytes,7,opt,name=level,proto3" json:"level,omitempty"`
	User          string                 `protobuf:"bytes,8,opt,name=user,proto3" json:"user,omitempty"`
	Description   string                 `protobuf:"bytes,9,opt,name=description,proto3" json:"description,omitempty"`
	Timestamp     string                 `protobuf:"bytes,10,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Tags          []string               `protobuf:"bytes,11,rep,name=tags,proto3" json:"tags,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogRequest) Reset() {
	*x = LogRequest{}
	mi := &file_logshipper_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogRequest) ProtoMessage() {}

func (x *LogRequest) ProtoReflect() protoreflect.Message {
	mi := &file_logshipper_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogRequest.ProtoReflect.Descriptor instead.
func (*LogRequest) Descriptor() ([]byte, []int) {
	return file_logshipper_proto_rawDescGZIP(), []int{0}
}

func (x *LogRequest) GetOrgId() string {
	if x != nil {
		return x.OrgId
	}
	return ""
}

func (x *LogRequest) GetAgentIp() string {
	if x != nil {
		return x.AgentIp
	}
	return ""
}

func (x *LogRequest) GetHostname() string {
	if x != nil {
		return x.Hostname
	}
	return ""
}

func (x *LogRequest) GetEventId() string {
	if x != nil {
		return x.EventId
	}
	return ""
}

func (x *LogRequest) GetLogName() string {
	if x != nil {
		return x.LogName
	}
	return ""
}

func (x *LogRequest) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

func (x *LogRequest) GetLevel() string {
	if x != nil {
		return x.Level
	}
	return ""
}

func (x *LogRequest) GetUser() string {
	if x != nil {
		return x.User
	}
	return ""
}

func (x *LogRequest) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *LogRequest) GetTimestamp() string {
	if x != nil {
		return x.Timestamp
	}
	return ""
}

func (x *LogRequest) GetTags() []string {
	if x != nil {
		return x.Tags
	}
	return nil
}

type LogResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Status        string                 `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogResponse) Reset() {
	*x = LogResponse{}
	mi := &file_logshipper_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogResponse) ProtoMessage() {}

func (x *LogResponse) ProtoReflect() protoreflect.Message {
	mi := &file_logshipper_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogResponse.ProtoReflect.Descriptor instead.
func (*LogResponse) Descriptor() ([]byte, []int) {
	return file_logshipper_proto_rawDescGZIP(), []int{1}
}

func (x *LogResponse) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

var File_logshipper_proto protoreflect.FileDescriptor

const file_logshipper_proto_rawDesc = "" +
	"\n" +
	"\x10logshipper.proto\x12\n" +
	"logshipper\"\xa6\x02\n" +
	"\n" +
	"LogRequest\x12\x15\n" +
	"\x06org_id\x18\x01 \x01(\tR\x05orgId\x12\x19\n" +
	"\bagent_ip\x18\x02 \x01(\tR\aagentIp\x12\x1a\n" +
	"\bhostname\x18\x03 \x01(\tR\bhostname\x12\x19\n" +
	"\bevent_id\x18\x04 \x01(\tR\aeventId\x12\x19\n" +
	"\blog_name\x18\x05 \x01(\tR\alogName\x12\x16\n" +
	"\x06source\x18\x06 \x01(\tR\x06source\x12\x14\n" +
	"\x05level\x18\a \x01(\tR\x05level\x12\x12\n" +
	"\x04user\x18\b \x01(\tR\x04user\x12 \n" +
	"\vdescription\x18\t \x01(\tR\vdescription\x12\x1c\n" +
	"\ttimestamp\x18\n" +
	" \x01(\tR\ttimestamp\x12\x12\n" +
	"\x04tags\x18\v \x03(\tR\x04tags\"%\n" +
	"\vLogResponse\x12\x16\n" +
	"\x06status\x18\x01 \x01(\tR\x06status2H\n" +
	"\n" +
	"LogService\x12:\n" +
	"\aSendLog\x12\x16.logshipper.LogRequest\x1a\x17.logshipper.LogResponseB\x04Z\x02./b\x06proto3"

var (
	file_logshipper_proto_rawDescOnce sync.Once
	file_logshipper_proto_rawDescData []byte
)

func file_logshipper_proto_rawDescGZIP() []byte {
	file_logshipper_proto_rawDescOnce.Do(func() {
		file_logshipper_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_logshipper_proto_rawDesc), len(file_logshipper_proto_rawDesc)))
	})
	return file_logshipper_proto_rawDescData
}

var file_logshipper_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_logshipper_proto_goTypes = []any{
	(*LogRequest)(nil),  // 0: logshipper.LogRequest
	(*LogResponse)(nil), // 1: logshipper.LogResponse
}
var file_logshipper_proto_depIdxs = []int32{
	0, // 0: logshipper.LogService.SendLog:input_type -> logshipper.LogRequest
	1, // 1: logshipper.LogService.SendLog:output_type -> logshipper.LogResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_logshipper_proto_init() }
func file_logshipper_proto_init() {
	if File_logshipper_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_logshipper_proto_rawDesc), len(file_logshipper_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_logshipper_proto_goTypes,
		DependencyIndexes: file_logshipper_proto_depIdxs,
		MessageInfos:      file_logshipper_proto_msgTypes,
	}.Build()
	File_logshipper_proto = out.File
	file_logshipper_proto_goTypes = nil
	file_logshipper_proto_depIdxs = nil
}
