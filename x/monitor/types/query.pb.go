// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: babylon/monitor/query.proto

package types

import (
	context "context"
	fmt "fmt"
	_ "github.com/cosmos/cosmos-sdk/types/query"
	_ "github.com/gogo/protobuf/gogoproto"
	grpc1 "github.com/gogo/protobuf/grpc"
	proto "github.com/gogo/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// QueryParamsRequest is request type for the Query/Params RPC method.
type QueryParamsRequest struct {
}

func (m *QueryParamsRequest) Reset()         { *m = QueryParamsRequest{} }
func (m *QueryParamsRequest) String() string { return proto.CompactTextString(m) }
func (*QueryParamsRequest) ProtoMessage()    {}
func (*QueryParamsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_3b70877a7534d1c4, []int{0}
}
func (m *QueryParamsRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryParamsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryParamsRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryParamsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryParamsRequest.Merge(m, src)
}
func (m *QueryParamsRequest) XXX_Size() int {
	return m.Size()
}
func (m *QueryParamsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryParamsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryParamsRequest proto.InternalMessageInfo

// QueryParamsResponse is response type for the Query/Params RPC method.
type QueryParamsResponse struct {
	// params holds all the parameters of this module.
	Params Params `protobuf:"bytes,1,opt,name=params,proto3" json:"params"`
}

func (m *QueryParamsResponse) Reset()         { *m = QueryParamsResponse{} }
func (m *QueryParamsResponse) String() string { return proto.CompactTextString(m) }
func (*QueryParamsResponse) ProtoMessage()    {}
func (*QueryParamsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_3b70877a7534d1c4, []int{1}
}
func (m *QueryParamsResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryParamsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryParamsResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryParamsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryParamsResponse.Merge(m, src)
}
func (m *QueryParamsResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryParamsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryParamsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryParamsResponse proto.InternalMessageInfo

func (m *QueryParamsResponse) GetParams() Params {
	if m != nil {
		return m.Params
	}
	return Params{}
}

type QueryFinishedEpochBtcHeightRequest struct {
	EpochNum uint64 `protobuf:"varint,1,opt,name=epoch_num,json=epochNum,proto3" json:"epoch_num,omitempty"`
}

func (m *QueryFinishedEpochBtcHeightRequest) Reset()         { *m = QueryFinishedEpochBtcHeightRequest{} }
func (m *QueryFinishedEpochBtcHeightRequest) String() string { return proto.CompactTextString(m) }
func (*QueryFinishedEpochBtcHeightRequest) ProtoMessage()    {}
func (*QueryFinishedEpochBtcHeightRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_3b70877a7534d1c4, []int{2}
}
func (m *QueryFinishedEpochBtcHeightRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryFinishedEpochBtcHeightRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryFinishedEpochBtcHeightRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryFinishedEpochBtcHeightRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryFinishedEpochBtcHeightRequest.Merge(m, src)
}
func (m *QueryFinishedEpochBtcHeightRequest) XXX_Size() int {
	return m.Size()
}
func (m *QueryFinishedEpochBtcHeightRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryFinishedEpochBtcHeightRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryFinishedEpochBtcHeightRequest proto.InternalMessageInfo

func (m *QueryFinishedEpochBtcHeightRequest) GetEpochNum() uint64 {
	if m != nil {
		return m.EpochNum
	}
	return 0
}

type QueryFinishedEpochBtcHeightResponse struct {
	// height of btc ligh client when epoch ended
	BtcLightClientHeight uint64 `protobuf:"varint,1,opt,name=btc_light_client_height,json=btcLightClientHeight,proto3" json:"btc_light_client_height,omitempty"`
}

func (m *QueryFinishedEpochBtcHeightResponse) Reset()         { *m = QueryFinishedEpochBtcHeightResponse{} }
func (m *QueryFinishedEpochBtcHeightResponse) String() string { return proto.CompactTextString(m) }
func (*QueryFinishedEpochBtcHeightResponse) ProtoMessage()    {}
func (*QueryFinishedEpochBtcHeightResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_3b70877a7534d1c4, []int{3}
}
func (m *QueryFinishedEpochBtcHeightResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryFinishedEpochBtcHeightResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryFinishedEpochBtcHeightResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryFinishedEpochBtcHeightResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryFinishedEpochBtcHeightResponse.Merge(m, src)
}
func (m *QueryFinishedEpochBtcHeightResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryFinishedEpochBtcHeightResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryFinishedEpochBtcHeightResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryFinishedEpochBtcHeightResponse proto.InternalMessageInfo

func (m *QueryFinishedEpochBtcHeightResponse) GetBtcLightClientHeight() uint64 {
	if m != nil {
		return m.BtcLightClientHeight
	}
	return 0
}

func init() {
	proto.RegisterType((*QueryParamsRequest)(nil), "babylon.monitor.v1.QueryParamsRequest")
	proto.RegisterType((*QueryParamsResponse)(nil), "babylon.monitor.v1.QueryParamsResponse")
	proto.RegisterType((*QueryFinishedEpochBtcHeightRequest)(nil), "babylon.monitor.v1.QueryFinishedEpochBtcHeightRequest")
	proto.RegisterType((*QueryFinishedEpochBtcHeightResponse)(nil), "babylon.monitor.v1.QueryFinishedEpochBtcHeightResponse")
}

func init() { proto.RegisterFile("babylon/monitor/query.proto", fileDescriptor_3b70877a7534d1c4) }

var fileDescriptor_3b70877a7534d1c4 = []byte{
	// 426 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x52, 0xcd, 0xaa, 0xd3, 0x40,
	0x14, 0x4e, 0x2e, 0xd7, 0xa2, 0xe3, 0x6e, 0x2c, 0x2a, 0xb9, 0x97, 0x5c, 0x8d, 0xe0, 0x15, 0x17,
	0x19, 0x72, 0xc5, 0x9f, 0xad, 0x15, 0x45, 0x41, 0xfc, 0xe9, 0x52, 0x84, 0x30, 0x33, 0x0e, 0xc9,
	0x40, 0x32, 0x27, 0xcd, 0x4c, 0x8a, 0x45, 0xba, 0xf1, 0x09, 0x04, 0xdf, 0xc4, 0xad, 0x2f, 0xd0,
	0x65, 0xc1, 0x8d, 0x2b, 0x91, 0xd6, 0x07, 0x91, 0x4c, 0xa6, 0x05, 0xdb, 0x5a, 0x71, 0x97, 0x9c,
	0xef, 0xe7, 0x7c, 0xe7, 0x9c, 0x41, 0x47, 0x8c, 0xb2, 0x49, 0x01, 0x8a, 0x94, 0xa0, 0xa4, 0x81,
	0x9a, 0x8c, 0x1a, 0x51, 0x4f, 0xe2, 0xaa, 0x06, 0x03, 0x18, 0x3b, 0x30, 0x76, 0x60, 0x3c, 0x4e,
	0x82, 0x7e, 0x06, 0x19, 0x58, 0x98, 0xb4, 0x5f, 0x1d, 0x33, 0x38, 0xce, 0x00, 0xb2, 0x42, 0x10,
	0x5a, 0x49, 0x42, 0x95, 0x02, 0x43, 0x8d, 0x04, 0xa5, 0x1d, 0x7a, 0x9b, 0x83, 0x2e, 0x41, 0x13,
	0x46, 0xb5, 0xe8, 0x1a, 0x90, 0x71, 0xc2, 0x84, 0xa1, 0x09, 0xa9, 0x68, 0x26, 0x95, 0x25, 0xaf,
	0x9c, 0x36, 0x03, 0x55, 0xb4, 0xa6, 0xa5, 0x73, 0x8a, 0xfa, 0x08, 0xbf, 0x6e, 0xf5, 0xaf, 0x6c,
	0x71, 0x28, 0x46, 0x8d, 0xd0, 0x26, 0x7a, 0x89, 0x2e, 0xfd, 0x51, 0xd5, 0x15, 0x28, 0x2d, 0xf0,
	0x03, 0xd4, 0xeb, 0xc4, 0x57, 0xfd, 0x6b, 0xfe, 0xad, 0x8b, 0x67, 0x41, 0xbc, 0x3d, 0x4f, 0xdc,
	0x69, 0x06, 0x87, 0xb3, 0x1f, 0x27, 0xde, 0xd0, 0xf1, 0xa3, 0x87, 0x28, 0xb2, 0x86, 0x4f, 0xa4,
	0x92, 0x3a, 0x17, 0xef, 0x1e, 0x57, 0xc0, 0xf3, 0x81, 0xe1, 0x4f, 0x85, 0xcc, 0x72, 0xe3, 0xda,
	0xe2, 0x23, 0x74, 0x41, 0xb4, 0x40, 0xaa, 0x9a, 0xd2, 0xb6, 0x38, 0x1c, 0x9e, 0xb7, 0x85, 0x17,
	0x4d, 0x19, 0xbd, 0x45, 0x37, 0xf6, 0x5a, 0xb8, 0x8c, 0x77, 0xd1, 0x15, 0x66, 0x78, 0x5a, 0xb4,
	0xc5, 0x94, 0x17, 0x52, 0x28, 0x93, 0xe6, 0x96, 0xe2, 0x1c, 0xfb, 0xcc, 0xf0, 0xe7, 0xed, 0xff,
	0x23, 0x0b, 0x76, 0xf2, 0xb3, 0xaf, 0x07, 0xe8, 0x9c, 0xb5, 0xc7, 0x53, 0xd4, 0xeb, 0x46, 0xc0,
	0x37, 0x77, 0x8d, 0xb7, 0xbd, 0xad, 0xe0, 0xf4, 0x9f, 0xbc, 0x2e, 0x5b, 0x14, 0x7d, 0xfc, 0xf6,
	0xeb, 0xf3, 0xc1, 0x31, 0x0e, 0xc8, 0xe6, 0x4d, 0xc6, 0x89, 0x3b, 0x0b, 0xfe, 0xe2, 0xa3, 0xcb,
	0xbb, 0x47, 0xc4, 0xf7, 0xfe, 0xda, 0x67, 0xef, 0x5a, 0x83, 0xfb, 0xff, 0xad, 0x73, 0x79, 0x4f,
	0x6d, 0xde, 0xeb, 0xf8, 0x64, 0x57, 0xde, 0x0f, 0xeb, 0x53, 0x4d, 0x07, 0xcf, 0x66, 0x8b, 0xd0,
	0x9f, 0x2f, 0x42, 0xff, 0xe7, 0x22, 0xf4, 0x3f, 0x2d, 0x43, 0x6f, 0xbe, 0x0c, 0xbd, 0xef, 0xcb,
	0xd0, 0x7b, 0x43, 0x32, 0x69, 0xf2, 0x86, 0xc5, 0x1c, 0xca, 0x95, 0x09, 0xcf, 0xa9, 0x54, 0x6b,
	0xc7, 0xf7, 0x6b, 0x4f, 0x33, 0xa9, 0x84, 0x66, 0x3d, 0xfb, 0x2e, 0xef, 0xfc, 0x0e, 0x00, 0x00,
	0xff, 0xff, 0x3f, 0x2c, 0xa9, 0x89, 0x48, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// QueryClient is the client API for Query service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type QueryClient interface {
	// Parameters queries the parameters of the module.
	Params(ctx context.Context, in *QueryParamsRequest, opts ...grpc.CallOption) (*QueryParamsResponse, error)
	// FinishedEpochBtcHeight btc light client height at provided epoch finish
	FinishedEpochBtcHeight(ctx context.Context, in *QueryFinishedEpochBtcHeightRequest, opts ...grpc.CallOption) (*QueryFinishedEpochBtcHeightResponse, error)
}

type queryClient struct {
	cc grpc1.ClientConn
}

func NewQueryClient(cc grpc1.ClientConn) QueryClient {
	return &queryClient{cc}
}

func (c *queryClient) Params(ctx context.Context, in *QueryParamsRequest, opts ...grpc.CallOption) (*QueryParamsResponse, error) {
	out := new(QueryParamsResponse)
	err := c.cc.Invoke(ctx, "/babylon.monitor.v1.Query/Params", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) FinishedEpochBtcHeight(ctx context.Context, in *QueryFinishedEpochBtcHeightRequest, opts ...grpc.CallOption) (*QueryFinishedEpochBtcHeightResponse, error) {
	out := new(QueryFinishedEpochBtcHeightResponse)
	err := c.cc.Invoke(ctx, "/babylon.monitor.v1.Query/FinishedEpochBtcHeight", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// QueryServer is the server API for Query service.
type QueryServer interface {
	// Parameters queries the parameters of the module.
	Params(context.Context, *QueryParamsRequest) (*QueryParamsResponse, error)
	// FinishedEpochBtcHeight btc light client height at provided epoch finish
	FinishedEpochBtcHeight(context.Context, *QueryFinishedEpochBtcHeightRequest) (*QueryFinishedEpochBtcHeightResponse, error)
}

// UnimplementedQueryServer can be embedded to have forward compatible implementations.
type UnimplementedQueryServer struct {
}

func (*UnimplementedQueryServer) Params(ctx context.Context, req *QueryParamsRequest) (*QueryParamsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Params not implemented")
}
func (*UnimplementedQueryServer) FinishedEpochBtcHeight(ctx context.Context, req *QueryFinishedEpochBtcHeightRequest) (*QueryFinishedEpochBtcHeightResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FinishedEpochBtcHeight not implemented")
}

func RegisterQueryServer(s grpc1.Server, srv QueryServer) {
	s.RegisterService(&_Query_serviceDesc, srv)
}

func _Query_Params_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryParamsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).Params(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/babylon.monitor.v1.Query/Params",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).Params(ctx, req.(*QueryParamsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_FinishedEpochBtcHeight_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryFinishedEpochBtcHeightRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).FinishedEpochBtcHeight(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/babylon.monitor.v1.Query/FinishedEpochBtcHeight",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).FinishedEpochBtcHeight(ctx, req.(*QueryFinishedEpochBtcHeightRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Query_serviceDesc = grpc.ServiceDesc{
	ServiceName: "babylon.monitor.v1.Query",
	HandlerType: (*QueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Params",
			Handler:    _Query_Params_Handler,
		},
		{
			MethodName: "FinishedEpochBtcHeight",
			Handler:    _Query_FinishedEpochBtcHeight_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "babylon/monitor/query.proto",
}

func (m *QueryParamsRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryParamsRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryParamsRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	return len(dAtA) - i, nil
}

func (m *QueryParamsResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryParamsResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryParamsResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		size, err := m.Params.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintQuery(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *QueryFinishedEpochBtcHeightRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryFinishedEpochBtcHeightRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryFinishedEpochBtcHeightRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.EpochNum != 0 {
		i = encodeVarintQuery(dAtA, i, uint64(m.EpochNum))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *QueryFinishedEpochBtcHeightResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryFinishedEpochBtcHeightResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryFinishedEpochBtcHeightResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.BtcLightClientHeight != 0 {
		i = encodeVarintQuery(dAtA, i, uint64(m.BtcLightClientHeight))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintQuery(dAtA []byte, offset int, v uint64) int {
	offset -= sovQuery(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *QueryParamsRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	return n
}

func (m *QueryParamsResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.Params.Size()
	n += 1 + l + sovQuery(uint64(l))
	return n
}

func (m *QueryFinishedEpochBtcHeightRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.EpochNum != 0 {
		n += 1 + sovQuery(uint64(m.EpochNum))
	}
	return n
}

func (m *QueryFinishedEpochBtcHeightResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.BtcLightClientHeight != 0 {
		n += 1 + sovQuery(uint64(m.BtcLightClientHeight))
	}
	return n
}

func sovQuery(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozQuery(x uint64) (n int) {
	return sovQuery(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *QueryParamsRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryParamsRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryParamsRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryParamsResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryParamsResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryParamsResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Params", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Params.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryFinishedEpochBtcHeightRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryFinishedEpochBtcHeightRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryFinishedEpochBtcHeightRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field EpochNum", wireType)
			}
			m.EpochNum = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.EpochNum |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryFinishedEpochBtcHeightResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryFinishedEpochBtcHeightResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryFinishedEpochBtcHeightResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field BtcLightClientHeight", wireType)
			}
			m.BtcLightClientHeight = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.BtcLightClientHeight |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipQuery(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthQuery
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupQuery
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthQuery
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthQuery        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowQuery          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupQuery = fmt.Errorf("proto: unexpected end of group")
)
