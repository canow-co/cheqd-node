// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cheqd/did/v2/genesis.proto

package types

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
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

// DidDocVersionSet contains all versions of DID Documents and their metadata for a given DID.
// The latest version of the DID Document set is stored in the latest_version field.
type DidDocVersionSet struct {
	// Latest version of the DID Document set
	LatestVersion string `protobuf:"bytes,1,opt,name=latest_version,json=latestVersion,proto3" json:"latest_version,omitempty"`
	// All versions of the DID Document set
	DidDocs []*DidDocWithMetadata `protobuf:"bytes,2,rep,name=did_docs,json=didDocs,proto3" json:"did_docs,omitempty"`
}

func (m *DidDocVersionSet) Reset()         { *m = DidDocVersionSet{} }
func (m *DidDocVersionSet) String() string { return proto.CompactTextString(m) }
func (*DidDocVersionSet) ProtoMessage()    {}
func (*DidDocVersionSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_83613517e395af68, []int{0}
}
func (m *DidDocVersionSet) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *DidDocVersionSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_DidDocVersionSet.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *DidDocVersionSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DidDocVersionSet.Merge(m, src)
}
func (m *DidDocVersionSet) XXX_Size() int {
	return m.Size()
}
func (m *DidDocVersionSet) XXX_DiscardUnknown() {
	xxx_messageInfo_DidDocVersionSet.DiscardUnknown(m)
}

var xxx_messageInfo_DidDocVersionSet proto.InternalMessageInfo

func (m *DidDocVersionSet) GetLatestVersion() string {
	if m != nil {
		return m.LatestVersion
	}
	return ""
}

func (m *DidDocVersionSet) GetDidDocs() []*DidDocWithMetadata {
	if m != nil {
		return m.DidDocs
	}
	return nil
}

// GenesisState defines the cheqd DID module's genesis state.
type GenesisState struct {
	// Namespace for the DID module
	// Example: mainnet, testnet, local
	DidNamespace string `protobuf:"bytes,1,opt,name=did_namespace,json=didNamespace,proto3" json:"did_namespace,omitempty"`
	// All DID Document version sets (contains all versions of all DID Documents)
	VersionSets []*DidDocVersionSet `protobuf:"bytes,2,rep,name=version_sets,json=versionSets,proto3" json:"version_sets,omitempty"`
	// Fee parameters for the DID module
	// Defines fixed fees and burn percentage for each DID operation type (create, update, delete)
	FeeParams *FeeParams `protobuf:"bytes,3,opt,name=fee_params,json=feeParams,proto3" json:"fee_params,omitempty"`
}

func (m *GenesisState) Reset()         { *m = GenesisState{} }
func (m *GenesisState) String() string { return proto.CompactTextString(m) }
func (*GenesisState) ProtoMessage()    {}
func (*GenesisState) Descriptor() ([]byte, []int) {
	return fileDescriptor_83613517e395af68, []int{1}
}
func (m *GenesisState) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GenesisState) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GenesisState.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GenesisState) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GenesisState.Merge(m, src)
}
func (m *GenesisState) XXX_Size() int {
	return m.Size()
}
func (m *GenesisState) XXX_DiscardUnknown() {
	xxx_messageInfo_GenesisState.DiscardUnknown(m)
}

var xxx_messageInfo_GenesisState proto.InternalMessageInfo

func (m *GenesisState) GetDidNamespace() string {
	if m != nil {
		return m.DidNamespace
	}
	return ""
}

func (m *GenesisState) GetVersionSets() []*DidDocVersionSet {
	if m != nil {
		return m.VersionSets
	}
	return nil
}

func (m *GenesisState) GetFeeParams() *FeeParams {
	if m != nil {
		return m.FeeParams
	}
	return nil
}

func init() {
	proto.RegisterType((*DidDocVersionSet)(nil), "cheqd.did.v2.DidDocVersionSet")
	proto.RegisterType((*GenesisState)(nil), "cheqd.did.v2.GenesisState")
}

func init() { proto.RegisterFile("cheqd/did/v2/genesis.proto", fileDescriptor_83613517e395af68) }

var fileDescriptor_83613517e395af68 = []byte{
	// 328 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x90, 0xc1, 0x4a, 0xc3, 0x40,
	0x10, 0x86, 0xbb, 0x16, 0xd4, 0x6e, 0x53, 0x91, 0x1c, 0xb4, 0xf6, 0xb0, 0x84, 0x8a, 0x50, 0x84,
	0x26, 0x10, 0xc1, 0x8b, 0x27, 0xa5, 0xe8, 0x49, 0x91, 0x14, 0x14, 0xbc, 0x84, 0xed, 0xce, 0xb4,
	0x5d, 0xb0, 0xd9, 0xd8, 0x1d, 0xa3, 0xbe, 0x85, 0x4f, 0xe2, 0x73, 0x78, 0xec, 0xd1, 0xa3, 0xb4,
	0x2f, 0x22, 0x26, 0xad, 0x1a, 0xf0, 0x36, 0x7c, 0xff, 0xcf, 0xff, 0xcf, 0x0c, 0x6f, 0xa9, 0x31,
	0x3e, 0x40, 0x00, 0x1a, 0x82, 0x2c, 0x0c, 0x46, 0x98, 0xa0, 0xd5, 0xd6, 0x4f, 0xa7, 0x86, 0x8c,
	0xeb, 0xe4, 0x9a, 0x0f, 0x1a, 0xfc, 0x2c, 0x6c, 0xed, 0x95, 0x9c, 0xa0, 0x01, 0x8c, 0x2a, 0x8c,
	0xad, 0x9d, 0x92, 0x34, 0x44, 0x2c, 0x78, 0x3b, 0xe3, 0xdb, 0x3d, 0x0d, 0x3d, 0xa3, 0x6e, 0x70,
	0x6a, 0xb5, 0x49, 0xfa, 0x48, 0xee, 0x01, 0xdf, 0xba, 0x97, 0x84, 0x96, 0xe2, 0xac, 0x80, 0x4d,
	0xe6, 0xb1, 0x4e, 0x2d, 0x6a, 0x14, 0x74, 0xe9, 0x74, 0x4f, 0xf8, 0x26, 0x68, 0x88, 0xc1, 0x28,
	0xdb, 0x5c, 0xf3, 0xaa, 0x9d, 0x7a, 0xe8, 0xf9, 0x7f, 0xd7, 0xf1, 0x8b, 0xe0, 0x5b, 0x4d, 0xe3,
	0x4b, 0x24, 0x09, 0x92, 0x64, 0xb4, 0x01, 0x39, 0xb3, 0xed, 0x37, 0xc6, 0x9d, 0x8b, 0xe2, 0x94,
	0x3e, 0x49, 0x42, 0x77, 0x9f, 0x37, 0xbe, 0xd3, 0x12, 0x39, 0x41, 0x9b, 0x4a, 0x85, 0xcb, 0x4e,
	0x07, 0x34, 0x5c, 0xad, 0x98, 0x7b, 0xca, 0x9d, 0xe5, 0x4a, 0xb1, 0x45, 0x5a, 0xd5, 0x8a, 0xff,
	0x6a, 0x7f, 0xef, 0x89, 0xea, 0xd9, 0xcf, 0x6c, 0xdd, 0x63, 0xce, 0x87, 0x88, 0x71, 0x2a, 0xa7,
	0x72, 0x62, 0x9b, 0x55, 0x8f, 0x75, 0xea, 0xe1, 0x6e, 0x39, 0xe0, 0x1c, 0xf1, 0x3a, 0x97, 0xa3,
	0xda, 0x70, 0x35, 0x9e, 0xf5, 0xde, 0xe7, 0x82, 0xcd, 0xe6, 0x82, 0x7d, 0xce, 0x05, 0x7b, 0x5d,
	0x88, 0xca, 0x6c, 0x21, 0x2a, 0x1f, 0x0b, 0x51, 0xb9, 0x3b, 0x1c, 0x69, 0x1a, 0x3f, 0x0e, 0x7c,
	0x65, 0x26, 0x81, 0x92, 0x89, 0x79, 0xea, 0x2a, 0x13, 0xe4, 0x81, 0xdd, 0xc4, 0x00, 0x06, 0xcf,
	0xf9, 0xd7, 0xe9, 0x25, 0x45, 0x3b, 0x58, 0xcf, 0xbf, 0x7e, 0xf4, 0x15, 0x00, 0x00, 0xff, 0xff,
	0x7b, 0x33, 0x7e, 0xff, 0xd4, 0x01, 0x00, 0x00,
}

func (m *DidDocVersionSet) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *DidDocVersionSet) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *DidDocVersionSet) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.DidDocs) > 0 {
		for iNdEx := len(m.DidDocs) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.DidDocs[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintGenesis(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x12
		}
	}
	if len(m.LatestVersion) > 0 {
		i -= len(m.LatestVersion)
		copy(dAtA[i:], m.LatestVersion)
		i = encodeVarintGenesis(dAtA, i, uint64(len(m.LatestVersion)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *GenesisState) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GenesisState) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GenesisState) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.FeeParams != nil {
		{
			size, err := m.FeeParams.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintGenesis(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if len(m.VersionSets) > 0 {
		for iNdEx := len(m.VersionSets) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.VersionSets[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintGenesis(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x12
		}
	}
	if len(m.DidNamespace) > 0 {
		i -= len(m.DidNamespace)
		copy(dAtA[i:], m.DidNamespace)
		i = encodeVarintGenesis(dAtA, i, uint64(len(m.DidNamespace)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintGenesis(dAtA []byte, offset int, v uint64) int {
	offset -= sovGenesis(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *DidDocVersionSet) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.LatestVersion)
	if l > 0 {
		n += 1 + l + sovGenesis(uint64(l))
	}
	if len(m.DidDocs) > 0 {
		for _, e := range m.DidDocs {
			l = e.Size()
			n += 1 + l + sovGenesis(uint64(l))
		}
	}
	return n
}

func (m *GenesisState) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.DidNamespace)
	if l > 0 {
		n += 1 + l + sovGenesis(uint64(l))
	}
	if len(m.VersionSets) > 0 {
		for _, e := range m.VersionSets {
			l = e.Size()
			n += 1 + l + sovGenesis(uint64(l))
		}
	}
	if m.FeeParams != nil {
		l = m.FeeParams.Size()
		n += 1 + l + sovGenesis(uint64(l))
	}
	return n
}

func sovGenesis(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozGenesis(x uint64) (n int) {
	return sovGenesis(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *DidDocVersionSet) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenesis
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
			return fmt.Errorf("proto: DidDocVersionSet: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: DidDocVersionSet: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field LatestVersion", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenesis
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGenesis
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthGenesis
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.LatestVersion = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DidDocs", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenesis
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
				return ErrInvalidLengthGenesis
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenesis
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.DidDocs = append(m.DidDocs, &DidDocWithMetadata{})
			if err := m.DidDocs[len(m.DidDocs)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenesis(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenesis
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
func (m *GenesisState) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenesis
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
			return fmt.Errorf("proto: GenesisState: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GenesisState: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DidNamespace", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenesis
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGenesis
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthGenesis
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.DidNamespace = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field VersionSets", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenesis
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
				return ErrInvalidLengthGenesis
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenesis
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.VersionSets = append(m.VersionSets, &DidDocVersionSet{})
			if err := m.VersionSets[len(m.VersionSets)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FeeParams", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenesis
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
				return ErrInvalidLengthGenesis
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenesis
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.FeeParams == nil {
				m.FeeParams = &FeeParams{}
			}
			if err := m.FeeParams.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenesis(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenesis
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
func skipGenesis(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowGenesis
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
					return 0, ErrIntOverflowGenesis
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
					return 0, ErrIntOverflowGenesis
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
				return 0, ErrInvalidLengthGenesis
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupGenesis
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthGenesis
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthGenesis        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowGenesis          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupGenesis = fmt.Errorf("proto: unexpected end of group")
)
