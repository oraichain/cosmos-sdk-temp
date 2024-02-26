// Code generated by MockGen. DO NOT EDIT.
// Source: types/module/mock_appmodule_test.go

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	json "encoding/json"
	reflect "reflect"

	appmodule "cosmossdk.io/core/appmodule"
	types "github.com/cometbft/cometbft/abci/types"
	client "github.com/cosmos/cosmos-sdk/client"
	codec "github.com/cosmos/cosmos-sdk/codec"
	types0 "github.com/cosmos/cosmos-sdk/codec/types"
	types1 "github.com/cosmos/cosmos-sdk/types"
	module "github.com/cosmos/cosmos-sdk/types/module"
	gomock "github.com/golang/mock/gomock"
)

// MockAppModuleWithAllExtensions is a mock of AppModuleWithAllExtensions interface.
type MockAppModuleWithAllExtensions struct {
	ctrl     *gomock.Controller
	recorder *MockAppModuleWithAllExtensionsMockRecorder
}

// MockAppModuleWithAllExtensionsMockRecorder is the mock recorder for MockAppModuleWithAllExtensions.
type MockAppModuleWithAllExtensionsMockRecorder struct {
	mock *MockAppModuleWithAllExtensions
}

// NewMockAppModuleWithAllExtensions creates a new mock instance.
func NewMockAppModuleWithAllExtensions(ctrl *gomock.Controller) *MockAppModuleWithAllExtensions {
	mock := &MockAppModuleWithAllExtensions{ctrl: ctrl}
	mock.recorder = &MockAppModuleWithAllExtensionsMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAppModuleWithAllExtensions) EXPECT() *MockAppModuleWithAllExtensionsMockRecorder {
	return m.recorder
}

// DefaultGenesis mocks base method.
func (m *MockAppModuleWithAllExtensions) DefaultGenesis(arg0 codec.JSONCodec) json.RawMessage {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DefaultGenesis", arg0)
	ret0, _ := ret[0].(json.RawMessage)
	return ret0
}

// DefaultGenesis indicates an expected call of DefaultGenesis.
func (mr *MockAppModuleWithAllExtensionsMockRecorder) DefaultGenesis(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DefaultGenesis", reflect.TypeOf((*MockAppModuleWithAllExtensions)(nil).DefaultGenesis), arg0)
}

// EndBlock mocks base method.
func (m *MockAppModuleWithAllExtensions) EndBlock(arg0 context.Context) ([]appmodule.ValidatorUpdate, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EndBlock", arg0)
	ret0, _ := ret[0].([]appmodule.ValidatorUpdate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EndBlock indicates an expected call of EndBlock.
func (mr *MockAppModuleWithAllExtensionsMockRecorder) EndBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EndBlock", reflect.TypeOf((*MockAppModuleWithAllExtensions)(nil).EndBlock), arg0)
}

// ExportGenesis mocks base method.
func (m *MockAppModuleWithAllExtensions) ExportGenesis(arg0 context.Context, arg1 codec.JSONCodec) json.RawMessage {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExportGenesis", arg0, arg1)
	ret0, _ := ret[0].(json.RawMessage)
	return ret0
}

// ExportGenesis indicates an expected call of ExportGenesis.
func (mr *MockAppModuleWithAllExtensionsMockRecorder) ExportGenesis(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExportGenesis", reflect.TypeOf((*MockAppModuleWithAllExtensions)(nil).ExportGenesis), arg0, arg1)
}

// InitGenesis mocks base method.
func (m *MockAppModuleWithAllExtensions) InitGenesis(arg0 context.Context, arg1 codec.JSONCodec, arg2 json.RawMessage) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "InitGenesis", arg0, arg1, arg2)
}

// InitGenesis indicates an expected call of InitGenesis.
func (mr *MockAppModuleWithAllExtensionsMockRecorder) InitGenesis(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitGenesis", reflect.TypeOf((*MockAppModuleWithAllExtensions)(nil).InitGenesis), arg0, arg1, arg2)
}

// IsAppModule mocks base method.
func (m *MockAppModuleWithAllExtensions) IsAppModule() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "IsAppModule")
}

// IsAppModule indicates an expected call of IsAppModule.
func (mr *MockAppModuleWithAllExtensionsMockRecorder) IsAppModule() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsAppModule", reflect.TypeOf((*MockAppModuleWithAllExtensions)(nil).IsAppModule))
}

// IsOnePerModuleType mocks base method.
func (m *MockAppModuleWithAllExtensions) IsOnePerModuleType() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "IsOnePerModuleType")
}

// IsOnePerModuleType indicates an expected call of IsOnePerModuleType.
func (mr *MockAppModuleWithAllExtensionsMockRecorder) IsOnePerModuleType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsOnePerModuleType", reflect.TypeOf((*MockAppModuleWithAllExtensions)(nil).IsOnePerModuleType))
}

// Name mocks base method.
func (m *MockAppModuleWithAllExtensions) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name.
func (mr *MockAppModuleWithAllExtensionsMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockAppModuleWithAllExtensions)(nil).Name))
}

// RegisterInterfaces mocks base method.
func (m *MockAppModuleWithAllExtensions) RegisterInterfaces(arg0 types0.InterfaceRegistry) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RegisterInterfaces", arg0)
}

// RegisterInterfaces indicates an expected call of RegisterInterfaces.
func (mr *MockAppModuleWithAllExtensionsMockRecorder) RegisterInterfaces(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterInterfaces", reflect.TypeOf((*MockAppModuleWithAllExtensions)(nil).RegisterInterfaces), arg0)
}

// RegisterInvariants mocks base method.
func (m *MockAppModuleWithAllExtensions) RegisterInvariants(arg0 types1.InvariantRegistry) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RegisterInvariants", arg0)
}

// RegisterInvariants indicates an expected call of RegisterInvariants.
func (mr *MockAppModuleWithAllExtensionsMockRecorder) RegisterInvariants(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterInvariants", reflect.TypeOf((*MockAppModuleWithAllExtensions)(nil).RegisterInvariants), arg0)
}

// RegisterServices mocks base method.
func (m *MockAppModuleWithAllExtensions) RegisterServices(arg0 module.Configurator) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RegisterServices", arg0)
}

// RegisterServices indicates an expected call of RegisterServices.
func (mr *MockAppModuleWithAllExtensionsMockRecorder) RegisterServices(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterServices", reflect.TypeOf((*MockAppModuleWithAllExtensions)(nil).RegisterServices), arg0)
}

// ValidateGenesis mocks base method.
func (m *MockAppModuleWithAllExtensions) ValidateGenesis(arg0 codec.JSONCodec, arg1 client.TxEncodingConfig, arg2 json.RawMessage) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateGenesis", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateGenesis indicates an expected call of ValidateGenesis.
func (mr *MockAppModuleWithAllExtensionsMockRecorder) ValidateGenesis(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateGenesis", reflect.TypeOf((*MockAppModuleWithAllExtensions)(nil).ValidateGenesis), arg0, arg1, arg2)
}

// MockAppModuleWithAllExtensionsABCI is a mock of AppModuleWithAllExtensionsABCI interface.
type MockAppModuleWithAllExtensionsABCI struct {
	ctrl     *gomock.Controller
	recorder *MockAppModuleWithAllExtensionsABCIMockRecorder
}

// MockAppModuleWithAllExtensionsABCIMockRecorder is the mock recorder for MockAppModuleWithAllExtensionsABCI.
type MockAppModuleWithAllExtensionsABCIMockRecorder struct {
	mock *MockAppModuleWithAllExtensionsABCI
}

// NewMockAppModuleWithAllExtensionsABCI creates a new mock instance.
func NewMockAppModuleWithAllExtensionsABCI(ctrl *gomock.Controller) *MockAppModuleWithAllExtensionsABCI {
	mock := &MockAppModuleWithAllExtensionsABCI{ctrl: ctrl}
	mock.recorder = &MockAppModuleWithAllExtensionsABCIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAppModuleWithAllExtensionsABCI) EXPECT() *MockAppModuleWithAllExtensionsABCIMockRecorder {
	return m.recorder
}

// DefaultGenesis mocks base method.
func (m *MockAppModuleWithAllExtensionsABCI) DefaultGenesis(arg0 codec.JSONCodec) json.RawMessage {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DefaultGenesis", arg0)
	ret0, _ := ret[0].(json.RawMessage)
	return ret0
}

// DefaultGenesis indicates an expected call of DefaultGenesis.
func (mr *MockAppModuleWithAllExtensionsABCIMockRecorder) DefaultGenesis(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DefaultGenesis", reflect.TypeOf((*MockAppModuleWithAllExtensionsABCI)(nil).DefaultGenesis), arg0)
}

// EndBlock mocks base method.
func (m *MockAppModuleWithAllExtensionsABCI) EndBlock(arg0 context.Context) ([]appmodule.ValidatorUpdate, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EndBlock", arg0)
	ret0, _ := ret[0].([]appmodule.ValidatorUpdate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EndBlock indicates an expected call of EndBlock.
func (mr *MockAppModuleWithAllExtensionsABCIMockRecorder) EndBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EndBlock", reflect.TypeOf((*MockAppModuleWithAllExtensionsABCI)(nil).EndBlock), arg0)
}

// ExportGenesis mocks base method.
func (m *MockAppModuleWithAllExtensionsABCI) ExportGenesis(arg0 context.Context, arg1 codec.JSONCodec) json.RawMessage {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExportGenesis", arg0, arg1)
	ret0, _ := ret[0].(json.RawMessage)
	return ret0
}

// ExportGenesis indicates an expected call of ExportGenesis.
func (mr *MockAppModuleWithAllExtensionsABCIMockRecorder) ExportGenesis(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExportGenesis", reflect.TypeOf((*MockAppModuleWithAllExtensionsABCI)(nil).ExportGenesis), arg0, arg1)
}

// InitGenesis mocks base method.
func (m *MockAppModuleWithAllExtensionsABCI) InitGenesis(arg0 context.Context, arg1 codec.JSONCodec, arg2 json.RawMessage) []types.ValidatorUpdate {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitGenesis", arg0, arg1, arg2)
	ret0, _ := ret[0].([]types.ValidatorUpdate)
	return ret0
}

// InitGenesis indicates an expected call of InitGenesis.
func (mr *MockAppModuleWithAllExtensionsABCIMockRecorder) InitGenesis(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitGenesis", reflect.TypeOf((*MockAppModuleWithAllExtensionsABCI)(nil).InitGenesis), arg0, arg1, arg2)
}

// IsAppModule mocks base method.
func (m *MockAppModuleWithAllExtensionsABCI) IsAppModule() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "IsAppModule")
}

// IsAppModule indicates an expected call of IsAppModule.
func (mr *MockAppModuleWithAllExtensionsABCIMockRecorder) IsAppModule() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsAppModule", reflect.TypeOf((*MockAppModuleWithAllExtensionsABCI)(nil).IsAppModule))
}

// IsOnePerModuleType mocks base method.
func (m *MockAppModuleWithAllExtensionsABCI) IsOnePerModuleType() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "IsOnePerModuleType")
}

// IsOnePerModuleType indicates an expected call of IsOnePerModuleType.
func (mr *MockAppModuleWithAllExtensionsABCIMockRecorder) IsOnePerModuleType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsOnePerModuleType", reflect.TypeOf((*MockAppModuleWithAllExtensionsABCI)(nil).IsOnePerModuleType))
}

// Name mocks base method.
func (m *MockAppModuleWithAllExtensionsABCI) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name.
func (mr *MockAppModuleWithAllExtensionsABCIMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockAppModuleWithAllExtensionsABCI)(nil).Name))
}

// RegisterInterfaces mocks base method.
func (m *MockAppModuleWithAllExtensionsABCI) RegisterInterfaces(arg0 types0.InterfaceRegistry) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RegisterInterfaces", arg0)
}

// RegisterInterfaces indicates an expected call of RegisterInterfaces.
func (mr *MockAppModuleWithAllExtensionsABCIMockRecorder) RegisterInterfaces(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterInterfaces", reflect.TypeOf((*MockAppModuleWithAllExtensionsABCI)(nil).RegisterInterfaces), arg0)
}

// RegisterInvariants mocks base method.
func (m *MockAppModuleWithAllExtensionsABCI) RegisterInvariants(arg0 types1.InvariantRegistry) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RegisterInvariants", arg0)
}

// RegisterInvariants indicates an expected call of RegisterInvariants.
func (mr *MockAppModuleWithAllExtensionsABCIMockRecorder) RegisterInvariants(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterInvariants", reflect.TypeOf((*MockAppModuleWithAllExtensionsABCI)(nil).RegisterInvariants), arg0)
}

// RegisterServices mocks base method.
func (m *MockAppModuleWithAllExtensionsABCI) RegisterServices(arg0 module.Configurator) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RegisterServices", arg0)
}

// RegisterServices indicates an expected call of RegisterServices.
func (mr *MockAppModuleWithAllExtensionsABCIMockRecorder) RegisterServices(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterServices", reflect.TypeOf((*MockAppModuleWithAllExtensionsABCI)(nil).RegisterServices), arg0)
}

// ValidateGenesis mocks base method.
func (m *MockAppModuleWithAllExtensionsABCI) ValidateGenesis(arg0 codec.JSONCodec, arg1 client.TxEncodingConfig, arg2 json.RawMessage) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateGenesis", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateGenesis indicates an expected call of ValidateGenesis.
func (mr *MockAppModuleWithAllExtensionsABCIMockRecorder) ValidateGenesis(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateGenesis", reflect.TypeOf((*MockAppModuleWithAllExtensionsABCI)(nil).ValidateGenesis), arg0, arg1, arg2)
}

// MockCoreAppModule is a mock of CoreAppModule interface.
type MockCoreAppModule struct {
	ctrl     *gomock.Controller
	recorder *MockCoreAppModuleMockRecorder
}

// MockCoreAppModuleMockRecorder is the mock recorder for MockCoreAppModule.
type MockCoreAppModuleMockRecorder struct {
	mock *MockCoreAppModule
}

// NewMockCoreAppModule creates a new mock instance.
func NewMockCoreAppModule(ctrl *gomock.Controller) *MockCoreAppModule {
	mock := &MockCoreAppModule{ctrl: ctrl}
	mock.recorder = &MockCoreAppModuleMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCoreAppModule) EXPECT() *MockCoreAppModuleMockRecorder {
	return m.recorder
}

// BeginBlock mocks base method.
func (m *MockCoreAppModule) BeginBlock(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BeginBlock", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// BeginBlock indicates an expected call of BeginBlock.
func (mr *MockCoreAppModuleMockRecorder) BeginBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BeginBlock", reflect.TypeOf((*MockCoreAppModule)(nil).BeginBlock), arg0)
}

// ConsensusVersion mocks base method.
func (m *MockCoreAppModule) ConsensusVersion() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConsensusVersion")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// ConsensusVersion indicates an expected call of ConsensusVersion.
func (mr *MockCoreAppModuleMockRecorder) ConsensusVersion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConsensusVersion", reflect.TypeOf((*MockCoreAppModule)(nil).ConsensusVersion))
}

// DefaultGenesis mocks base method.
func (m *MockCoreAppModule) DefaultGenesis(arg0 appmodule.GenesisTarget) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DefaultGenesis", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DefaultGenesis indicates an expected call of DefaultGenesis.
func (mr *MockCoreAppModuleMockRecorder) DefaultGenesis(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DefaultGenesis", reflect.TypeOf((*MockCoreAppModule)(nil).DefaultGenesis), arg0)
}

// EndBlock mocks base method.
func (m *MockCoreAppModule) EndBlock(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EndBlock", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// EndBlock indicates an expected call of EndBlock.
func (mr *MockCoreAppModuleMockRecorder) EndBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EndBlock", reflect.TypeOf((*MockCoreAppModule)(nil).EndBlock), arg0)
}

// ExportGenesis mocks base method.
func (m *MockCoreAppModule) ExportGenesis(arg0 context.Context, arg1 appmodule.GenesisTarget) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExportGenesis", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ExportGenesis indicates an expected call of ExportGenesis.
func (mr *MockCoreAppModuleMockRecorder) ExportGenesis(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExportGenesis", reflect.TypeOf((*MockCoreAppModule)(nil).ExportGenesis), arg0, arg1)
}

// InitGenesis mocks base method.
func (m *MockCoreAppModule) InitGenesis(arg0 context.Context, arg1 appmodule.GenesisSource) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitGenesis", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// InitGenesis indicates an expected call of InitGenesis.
func (mr *MockCoreAppModuleMockRecorder) InitGenesis(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitGenesis", reflect.TypeOf((*MockCoreAppModule)(nil).InitGenesis), arg0, arg1)
}

// IsAppModule mocks base method.
func (m *MockCoreAppModule) IsAppModule() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "IsAppModule")
}

// IsAppModule indicates an expected call of IsAppModule.
func (mr *MockCoreAppModuleMockRecorder) IsAppModule() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsAppModule", reflect.TypeOf((*MockCoreAppModule)(nil).IsAppModule))
}

// IsOnePerModuleType mocks base method.
func (m *MockCoreAppModule) IsOnePerModuleType() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "IsOnePerModuleType")
}

// IsOnePerModuleType indicates an expected call of IsOnePerModuleType.
func (mr *MockCoreAppModuleMockRecorder) IsOnePerModuleType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsOnePerModuleType", reflect.TypeOf((*MockCoreAppModule)(nil).IsOnePerModuleType))
}

// Precommit mocks base method.
func (m *MockCoreAppModule) Precommit(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Precommit", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Precommit indicates an expected call of Precommit.
func (mr *MockCoreAppModuleMockRecorder) Precommit(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Precommit", reflect.TypeOf((*MockCoreAppModule)(nil).Precommit), arg0)
}

// PrepareCheckState mocks base method.
func (m *MockCoreAppModule) PrepareCheckState(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrepareCheckState", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// PrepareCheckState indicates an expected call of PrepareCheckState.
func (mr *MockCoreAppModuleMockRecorder) PrepareCheckState(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrepareCheckState", reflect.TypeOf((*MockCoreAppModule)(nil).PrepareCheckState), arg0)
}

// ValidateGenesis mocks base method.
func (m *MockCoreAppModule) ValidateGenesis(arg0 appmodule.GenesisSource) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateGenesis", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateGenesis indicates an expected call of ValidateGenesis.
func (mr *MockCoreAppModuleMockRecorder) ValidateGenesis(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateGenesis", reflect.TypeOf((*MockCoreAppModule)(nil).ValidateGenesis), arg0)
}

// MockCoreAppModuleWithPreBlock is a mock of CoreAppModuleWithPreBlock interface.
type MockCoreAppModuleWithPreBlock struct {
	ctrl     *gomock.Controller
	recorder *MockCoreAppModuleWithPreBlockMockRecorder
}

// MockCoreAppModuleWithPreBlockMockRecorder is the mock recorder for MockCoreAppModuleWithPreBlock.
type MockCoreAppModuleWithPreBlockMockRecorder struct {
	mock *MockCoreAppModuleWithPreBlock
}

// NewMockCoreAppModuleWithPreBlock creates a new mock instance.
func NewMockCoreAppModuleWithPreBlock(ctrl *gomock.Controller) *MockCoreAppModuleWithPreBlock {
	mock := &MockCoreAppModuleWithPreBlock{ctrl: ctrl}
	mock.recorder = &MockCoreAppModuleWithPreBlockMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCoreAppModuleWithPreBlock) EXPECT() *MockCoreAppModuleWithPreBlockMockRecorder {
	return m.recorder
}

// BeginBlock mocks base method.
func (m *MockCoreAppModuleWithPreBlock) BeginBlock(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BeginBlock", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// BeginBlock indicates an expected call of BeginBlock.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) BeginBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BeginBlock", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).BeginBlock), arg0)
}

// ConsensusVersion mocks base method.
func (m *MockCoreAppModuleWithPreBlock) ConsensusVersion() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConsensusVersion")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// ConsensusVersion indicates an expected call of ConsensusVersion.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) ConsensusVersion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConsensusVersion", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).ConsensusVersion))
}

// DefaultGenesis mocks base method.
func (m *MockCoreAppModuleWithPreBlock) DefaultGenesis(arg0 appmodule.GenesisTarget) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DefaultGenesis", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DefaultGenesis indicates an expected call of DefaultGenesis.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) DefaultGenesis(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DefaultGenesis", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).DefaultGenesis), arg0)
}

// EndBlock mocks base method.
func (m *MockCoreAppModuleWithPreBlock) EndBlock(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EndBlock", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// EndBlock indicates an expected call of EndBlock.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) EndBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EndBlock", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).EndBlock), arg0)
}

// ExportGenesis mocks base method.
func (m *MockCoreAppModuleWithPreBlock) ExportGenesis(arg0 context.Context, arg1 appmodule.GenesisTarget) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExportGenesis", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ExportGenesis indicates an expected call of ExportGenesis.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) ExportGenesis(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExportGenesis", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).ExportGenesis), arg0, arg1)
}

// InitGenesis mocks base method.
func (m *MockCoreAppModuleWithPreBlock) InitGenesis(arg0 context.Context, arg1 appmodule.GenesisSource) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitGenesis", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// InitGenesis indicates an expected call of InitGenesis.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) InitGenesis(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitGenesis", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).InitGenesis), arg0, arg1)
}

// IsAppModule mocks base method.
func (m *MockCoreAppModuleWithPreBlock) IsAppModule() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "IsAppModule")
}

// IsAppModule indicates an expected call of IsAppModule.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) IsAppModule() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsAppModule", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).IsAppModule))
}

// IsOnePerModuleType mocks base method.
func (m *MockCoreAppModuleWithPreBlock) IsOnePerModuleType() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "IsOnePerModuleType")
}

// IsOnePerModuleType indicates an expected call of IsOnePerModuleType.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) IsOnePerModuleType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsOnePerModuleType", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).IsOnePerModuleType))
}

// PreBlock mocks base method.
func (m *MockCoreAppModuleWithPreBlock) PreBlock(arg0 context.Context) (appmodule.ResponsePreBlock, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PreBlock", arg0)
	ret0, _ := ret[0].(appmodule.ResponsePreBlock)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PreBlock indicates an expected call of PreBlock.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) PreBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PreBlock", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).PreBlock), arg0)
}

// Precommit mocks base method.
func (m *MockCoreAppModuleWithPreBlock) Precommit(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Precommit", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Precommit indicates an expected call of Precommit.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) Precommit(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Precommit", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).Precommit), arg0)
}

// PrepareCheckState mocks base method.
func (m *MockCoreAppModuleWithPreBlock) PrepareCheckState(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrepareCheckState", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// PrepareCheckState indicates an expected call of PrepareCheckState.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) PrepareCheckState(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrepareCheckState", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).PrepareCheckState), arg0)
}

// ValidateGenesis mocks base method.
func (m *MockCoreAppModuleWithPreBlock) ValidateGenesis(arg0 appmodule.GenesisSource) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateGenesis", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateGenesis indicates an expected call of ValidateGenesis.
func (mr *MockCoreAppModuleWithPreBlockMockRecorder) ValidateGenesis(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateGenesis", reflect.TypeOf((*MockCoreAppModuleWithPreBlock)(nil).ValidateGenesis), arg0)
}
