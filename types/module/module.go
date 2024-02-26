/*
Package module contains application module patterns and associated "manager" functionality.
The module pattern has been broken down by:
  - inter-dependent module simulation functionality (AppModuleSimulation)
  - inter-dependent module full functionality (AppModule)

inter-dependent module functionality is module functionality which somehow
depends on other modules, typically through the module keeper.  Many of the
module keepers are dependent on each other, thus in order to access the full
set of module functionality we need to define all the keepers/params-store/keys
etc. This full set of advanced functionality is defined by the AppModule interface.

Independent module functions of modules can be accessed through a non instantiated AppModule.

Lastly the interface for genesis functionality (HasGenesis & HasABCIGenesis) has been
separated out from full module functionality (AppModule) so that modules which
are only used for genesis can take advantage of the Module patterns without
needlessly defining many placeholder functions
*/
package module

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtcryptoproto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"

	"cosmossdk.io/core/appmodule"
	"cosmossdk.io/core/genesis"
	errorsmod "cosmossdk.io/errors"
	storetypes "cosmossdk.io/store/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// Deprecated: use the embed extension interfaces instead, when needed.
type AppModuleBasic interface {
	HasName
	HasRegisterInterfaces
	HasGRPCGateway
	HasAminoCodec
}

// AppModule is the form for an application module. Most of
// its functionality has been moved to extension interfaces.
// Deprecated: use appmodule.AppModule with a combination of extension interfaces interfaces instead.
type AppModule interface {
	appmodule.AppModule

	HasName
	HasRegisterInterfaces
}

// HasName allows the module to provide its own name for legacy purposes.
// Newer apps should specify the name for their modules using a map
// using NewManagerFromMap.
type HasName interface {
	Name() string
}

// HasGenesisBasics is the legacy interface for stateless genesis methods.
type HasGenesisBasics interface {
	HasName

	DefaultGenesis(codec.JSONCodec) json.RawMessage
	ValidateGenesis(codec.JSONCodec, client.TxEncodingConfig, json.RawMessage) error
}

// HasAminoCodec is the interface for modules that have amino codec registration.
// Deprecated: modules should not need to register their own amino codecs.
type HasAminoCodec interface {
	RegisterLegacyAminoCodec(*codec.LegacyAmino)
}

// HasRegisterInterfaces is the interface for modules to register their msg types.
type HasRegisterInterfaces interface {
	RegisterInterfaces(types.InterfaceRegistry)
}

// HasGRPCGateway is the interface for modules to register their gRPC gateway routes.
type HasGRPCGateway interface {
	RegisterGRPCGatewayRoutes(client.Context, *runtime.ServeMux)
}

// HasGenesis is the extension interface for stateful genesis methods.
type HasGenesis interface {
	HasGenesisBasics
	InitGenesis(context.Context, codec.JSONCodec, json.RawMessage)
	ExportGenesis(context.Context, codec.JSONCodec) json.RawMessage
}

// HasABCIGenesis is the extension interface for stateful genesis methods which returns validator updates.
type HasABCIGenesis interface {
	HasGenesisBasics
	InitGenesis(context.Context, codec.JSONCodec, json.RawMessage) []abci.ValidatorUpdate
	ExportGenesis(context.Context, codec.JSONCodec) json.RawMessage
}

// HasInvariants is the interface for registering invariants.
type HasInvariants interface {
	// RegisterInvariants registers module invariants.
	RegisterInvariants(sdk.InvariantRegistry)
}

// HasServices is the interface for modules to register services.
type HasServices interface {
	// RegisterServices allows a module to register services.
	RegisterServices(Configurator)
}

// HasABCIEndBlock is the interface for modules that need to run code at the end of the block.
type HasABCIEndBlock interface {
	AppModule
	EndBlock(context.Context) ([]appmodule.ValidatorUpdate, error)
}

// Manager defines a module manager that provides the high level utility for managing and executing
// operations for a group of modules
type Manager struct {
	Modules                  map[string]appmodule.AppModule
	OrderInitGenesis         []string
	OrderExportGenesis       []string
	OrderPreBlockers         []string
	OrderBeginBlockers       []string
	OrderEndBlockers         []string
	OrderPrepareCheckStaters []string
	OrderPrecommiters        []string
	OrderMigrations          []string
}

// NewManager creates a new Manager object.
func NewManager(modules ...AppModule) *Manager {
	moduleMap := make(map[string]appmodule.AppModule)
	modulesStr := make([]string, 0, len(modules))
	preBlockModulesStr := make([]string, 0)
	for _, module := range modules {
		if _, ok := module.(appmodule.AppModule); !ok {
			panic(fmt.Sprintf("module %s does not implement appmodule.AppModule", module.Name()))
		}

		moduleMap[module.Name()] = module
		modulesStr = append(modulesStr, module.Name())
		if _, ok := module.(appmodule.HasPreBlocker); ok {
			preBlockModulesStr = append(preBlockModulesStr, module.Name())
		}
	}

	return &Manager{
		Modules:                  moduleMap,
		OrderInitGenesis:         modulesStr,
		OrderExportGenesis:       modulesStr,
		OrderPreBlockers:         preBlockModulesStr,
		OrderBeginBlockers:       modulesStr,
		OrderPrepareCheckStaters: modulesStr,
		OrderPrecommiters:        modulesStr,
		OrderEndBlockers:         modulesStr,
	}
}

// NewManagerFromMap creates a new Manager object from a map of module names to module implementations.
// This method should be used for apps and modules which have migrated to the cosmossdk.io/core.appmodule.AppModule API.
func NewManagerFromMap(moduleMap map[string]appmodule.AppModule) *Manager {
	simpleModuleMap := make(map[string]appmodule.AppModule)
	modulesStr := make([]string, 0, len(simpleModuleMap))
	preBlockModulesStr := make([]string, 0)
	for name, module := range moduleMap {
		simpleModuleMap[name] = module
		modulesStr = append(modulesStr, name)
		if _, ok := module.(appmodule.HasPreBlocker); ok {
			preBlockModulesStr = append(preBlockModulesStr, name)
		}
	}

	// Sort the modules by name. Given that we are using a map above we can't guarantee the order.
	sort.Strings(modulesStr)

	return &Manager{
		Modules:                  simpleModuleMap,
		OrderInitGenesis:         modulesStr,
		OrderExportGenesis:       modulesStr,
		OrderPreBlockers:         preBlockModulesStr,
		OrderBeginBlockers:       modulesStr,
		OrderEndBlockers:         modulesStr,
		OrderPrecommiters:        modulesStr,
		OrderPrepareCheckStaters: modulesStr,
	}
}

// SetOrderInitGenesis sets the order of init genesis calls
func (m *Manager) SetOrderInitGenesis(moduleNames ...string) {
	m.assertNoForgottenModules("SetOrderInitGenesis", moduleNames, func(moduleName string) bool {
		module := m.Modules[moduleName]
		if _, hasGenesis := module.(appmodule.HasGenesis); hasGenesis {
			return !hasGenesis
		}

		if _, hasABCIGenesis := module.(HasABCIGenesis); hasABCIGenesis {
			return !hasABCIGenesis
		}

		_, hasGenesis := module.(HasGenesis)
		return !hasGenesis
	})
	m.OrderInitGenesis = moduleNames
}

// SetOrderExportGenesis sets the order of export genesis calls
func (m *Manager) SetOrderExportGenesis(moduleNames ...string) {
	m.assertNoForgottenModules("SetOrderExportGenesis", moduleNames, func(moduleName string) bool {
		module := m.Modules[moduleName]
		if _, hasGenesis := module.(appmodule.HasGenesis); hasGenesis {
			return !hasGenesis
		}

		if _, hasABCIGenesis := module.(HasABCIGenesis); hasABCIGenesis {
			return !hasABCIGenesis
		}

		_, hasGenesis := module.(HasGenesis)
		return !hasGenesis
	})
	m.OrderExportGenesis = moduleNames
}

// SetOrderPreBlockers sets the order of set pre-blocker calls
func (m *Manager) SetOrderPreBlockers(moduleNames ...string) {
	m.assertNoForgottenModules("SetOrderPreBlockers", moduleNames,
		func(moduleName string) bool {
			module := m.Modules[moduleName]
			_, hasBlock := module.(appmodule.HasPreBlocker)
			return !hasBlock
		})
	m.OrderPreBlockers = moduleNames
}

// SetOrderBeginBlockers sets the order of set begin-blocker calls
func (m *Manager) SetOrderBeginBlockers(moduleNames ...string) {
	m.assertNoForgottenModules("SetOrderBeginBlockers", moduleNames,
		func(moduleName string) bool {
			module := m.Modules[moduleName]
			_, hasBeginBlock := module.(appmodule.HasBeginBlocker)
			return !hasBeginBlock
		})
	m.OrderBeginBlockers = moduleNames
}

// SetOrderEndBlockers sets the order of set end-blocker calls
func (m *Manager) SetOrderEndBlockers(moduleNames ...string) {
	m.assertNoForgottenModules("SetOrderEndBlockers", moduleNames,
		func(moduleName string) bool {
			module := m.Modules[moduleName]
			if _, hasEndBlock := module.(appmodule.HasEndBlocker); hasEndBlock {
				return !hasEndBlock
			}

			_, hasABCIEndBlock := module.(HasABCIEndBlock)
			return !hasABCIEndBlock
		})
	m.OrderEndBlockers = moduleNames
}

// SetOrderPrepareCheckStaters sets the order of set prepare-check-stater calls
func (m *Manager) SetOrderPrepareCheckStaters(moduleNames ...string) {
	m.assertNoForgottenModules("SetOrderPrepareCheckStaters", moduleNames,
		func(moduleName string) bool {
			module := m.Modules[moduleName]
			_, hasPrepareCheckState := module.(appmodule.HasPrepareCheckState)
			return !hasPrepareCheckState
		})
	m.OrderPrepareCheckStaters = moduleNames
}

// SetOrderPrecommiters sets the order of set precommiter calls
func (m *Manager) SetOrderPrecommiters(moduleNames ...string) {
	m.assertNoForgottenModules("SetOrderPrecommiters", moduleNames,
		func(moduleName string) bool {
			module := m.Modules[moduleName]
			_, hasPrecommit := module.(appmodule.HasPrecommit)
			return !hasPrecommit
		})
	m.OrderPrecommiters = moduleNames
}

// SetOrderMigrations sets the order of migrations to be run. If not set
// then migrations will be run with an order defined in `DefaultMigrationsOrder`.
func (m *Manager) SetOrderMigrations(moduleNames ...string) {
	m.assertNoForgottenModules("SetOrderMigrations", moduleNames, nil)
	m.OrderMigrations = moduleNames
}

// RegisterLegacyAminoCodec registers all module codecs
func (m *Manager) RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	for _, b := range m.Modules {
		if mod, ok := b.(HasAminoCodec); ok {
			mod.RegisterLegacyAminoCodec(cdc)
		}
	}
}

// RegisterInterfaces registers all module interface types
func (m *Manager) RegisterInterfaces(registry types.InterfaceRegistry) {
	for _, b := range m.Modules {
		if mod, ok := b.(HasRegisterInterfaces); ok {
			mod.RegisterInterfaces(registry)
		}
	}
}

// DefaultGenesis provides default genesis information for all modules
func (m *Manager) DefaultGenesis(cdc codec.JSONCodec) map[string]json.RawMessage {
	genesisData := make(map[string]json.RawMessage)
	for _, b := range m.Modules {
		if mod, ok := b.(HasGenesisBasics); ok {
			genesisData[mod.Name()] = mod.DefaultGenesis(cdc)
		} else if mod, ok := b.(HasName); ok {
			genesisData[mod.Name()] = []byte("{}")
		}
	}

	return genesisData
}

// ValidateGenesis performs genesis state validation for all modules
func (m *Manager) ValidateGenesis(cdc codec.JSONCodec, txEncCfg client.TxEncodingConfig, genesisData map[string]json.RawMessage) error {
	for _, b := range m.Modules {
		// first check if the module is an adapted Core API Module
		if mod, ok := b.(HasGenesisBasics); ok {
			if err := mod.ValidateGenesis(cdc, txEncCfg, genesisData[mod.Name()]); err != nil {
				return err
			}
		}
	}

	return nil
}

// RegisterGRPCGatewayRoutes registers all module rest routes
func (m *Manager) RegisterGRPCGatewayRoutes(clientCtx client.Context, rtr *runtime.ServeMux) {
	for _, b := range m.Modules {
		if mod, ok := b.(HasGRPCGateway); ok {
			mod.RegisterGRPCGatewayRoutes(clientCtx, rtr)
		}
	}
}

// AddTxCommands adds all tx commands to the rootTxCmd.
func (m *Manager) AddTxCommands(rootTxCmd *cobra.Command) {
	for _, b := range m.Modules {
		if mod, ok := b.(interface {
			GetTxCmd() *cobra.Command
		}); ok {
			if cmd := mod.GetTxCmd(); cmd != nil {
				rootTxCmd.AddCommand(cmd)
			}
		}
	}
}

// AddQueryCommands adds all query commands to the rootQueryCmd.
func (m *Manager) AddQueryCommands(rootQueryCmd *cobra.Command) {
	for _, b := range m.Modules {
		if mod, ok := b.(interface {
			GetQueryCmd() *cobra.Command
		}); ok {
			if cmd := mod.GetQueryCmd(); cmd != nil {
				rootQueryCmd.AddCommand(cmd)
			}
		}
	}
}

// RegisterInvariants registers all module invariants
func (m *Manager) RegisterInvariants(ir sdk.InvariantRegistry) {
	for _, module := range m.Modules {
		if module, ok := module.(HasInvariants); ok {
			module.RegisterInvariants(ir)
		}
	}
}

// RegisterServices registers all module services
func (m *Manager) RegisterServices(cfg Configurator) error {
	for _, module := range m.Modules {
		if module, ok := module.(HasServices); ok {
			module.RegisterServices(cfg)
		}

		if module, ok := module.(appmodule.HasServices); ok {
			err := module.RegisterServices(cfg)
			if err != nil {
				return err
			}
		}

		if module, ok := module.(appmodule.HasMigrations); ok {
			err := module.RegisterMigrations(cfg)
			if err != nil {
				return err
			}
		}

		if cfg.Error() != nil {
			return cfg.Error()
		}
	}

	return nil
}

// InitGenesis performs init genesis functionality for modules. Exactly one
// module must return a non-empty validator set update to correctly initialize
// the chain.
func (m *Manager) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, genesisData map[string]json.RawMessage) (*abci.ResponseInitChain, error) {
	var validatorUpdates []abci.ValidatorUpdate
	ctx.Logger().Info("initializing blockchain state from genesis.json")
	for _, moduleName := range m.OrderInitGenesis {
		if genesisData[moduleName] == nil {
			continue
		}

		mod := m.Modules[moduleName]
		// we might get an adapted module, a native core API module or a legacy module
		if module, ok := mod.(appmodule.HasGenesis); ok {
			ctx.Logger().Debug("running initialization for module", "module", moduleName)
			// core API genesis
			source, err := genesis.SourceFromRawJSON(genesisData[moduleName])
			if err != nil {
				return &abci.ResponseInitChain{}, err
			}

			err = module.InitGenesis(ctx, source)
			if err != nil {
				return &abci.ResponseInitChain{}, err
			}
		} else if module, ok := mod.(HasGenesis); ok {
			ctx.Logger().Debug("running initialization for module", "module", moduleName)
			module.InitGenesis(ctx, cdc, genesisData[moduleName])
		} else if module, ok := mod.(HasABCIGenesis); ok {
			ctx.Logger().Debug("running initialization for module", "module", moduleName)
			moduleValUpdates := module.InitGenesis(ctx, cdc, genesisData[moduleName])

			// use these validator updates if provided, the module manager assumes
			// only one module will update the validator set
			if len(moduleValUpdates) > 0 {
				if len(validatorUpdates) > 0 {
					return &abci.ResponseInitChain{}, errors.New("validator InitGenesis updates already set by a previous module")
				}
				validatorUpdates = moduleValUpdates
			}
		}
	}

	// a chain must initialize with a non-empty validator set
	if len(validatorUpdates) == 0 {
		return &abci.ResponseInitChain{}, fmt.Errorf("validator set is empty after InitGenesis, please ensure at least one validator is initialized with a delegation greater than or equal to the DefaultPowerReduction (%d)", sdk.DefaultPowerReduction)
	}

	return &abci.ResponseInitChain{
		Validators: validatorUpdates,
	}, nil
}

// ExportGenesis performs export genesis functionality for modules
func (m *Manager) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) (map[string]json.RawMessage, error) {
	return m.ExportGenesisForModules(ctx, cdc, []string{})
}

// ExportGenesisForModules performs export genesis functionality for modules
func (m *Manager) ExportGenesisForModules(ctx sdk.Context, cdc codec.JSONCodec, modulesToExport []string) (map[string]json.RawMessage, error) {
	if len(modulesToExport) == 0 {
		modulesToExport = m.OrderExportGenesis
	}
	// verify modules exists in app, so that we don't panic in the middle of an export
	if err := m.checkModulesExists(modulesToExport); err != nil {
		return nil, err
	}

	type genesisResult struct {
		bz  json.RawMessage
		err error
	}

	channels := make(map[string]chan genesisResult)
	for _, moduleName := range modulesToExport {
		mod := m.Modules[moduleName]
		if module, ok := mod.(appmodule.HasGenesis); ok {
			// core API genesis
			channels[moduleName] = make(chan genesisResult)
			go func(module appmodule.HasGenesis, ch chan genesisResult) {
				ctx := ctx.WithGasMeter(storetypes.NewInfiniteGasMeter()) // avoid race conditions
				target := genesis.RawJSONTarget{}
				err := module.ExportGenesis(ctx, target.Target())
				if err != nil {
					ch <- genesisResult{nil, err}
					return
				}

				rawJSON, err := target.JSON()
				if err != nil {
					ch <- genesisResult{nil, err}
					return
				}

				ch <- genesisResult{rawJSON, nil}
			}(module, channels[moduleName])
		} else if module, ok := mod.(HasGenesis); ok {
			channels[moduleName] = make(chan genesisResult)
			go func(module HasGenesis, ch chan genesisResult) {
				ctx := ctx.WithGasMeter(storetypes.NewInfiniteGasMeter()) // avoid race conditions
				ch <- genesisResult{module.ExportGenesis(ctx, cdc), nil}
			}(module, channels[moduleName])
		} else if module, ok := mod.(HasABCIGenesis); ok {
			channels[moduleName] = make(chan genesisResult)
			go func(module HasABCIGenesis, ch chan genesisResult) {
				ctx := ctx.WithGasMeter(storetypes.NewInfiniteGasMeter()) // avoid race conditions
				ch <- genesisResult{module.ExportGenesis(ctx, cdc), nil}
			}(module, channels[moduleName])
		}
	}

	genesisData := make(map[string]json.RawMessage)
	for moduleName := range channels {
		res := <-channels[moduleName]
		if res.err != nil {
			return nil, fmt.Errorf("genesis export error in %s: %w", moduleName, res.err)
		}

		genesisData[moduleName] = res.bz
	}

	return genesisData, nil
}

// checkModulesExists verifies that all modules in the list exist in the app
func (m *Manager) checkModulesExists(moduleName []string) error {
	for _, name := range moduleName {
		if _, ok := m.Modules[name]; !ok {
			return fmt.Errorf("module %s does not exist", name)
		}
	}

	return nil
}

// assertNoForgottenModules checks that we didn't forget any modules in the SetOrder* functions.
// `pass` is a closure which allows one to omit modules from `moduleNames`.
// If you provide non-nil `pass` and it returns true, the module would not be subject of the assertion.
func (m *Manager) assertNoForgottenModules(setOrderFnName string, moduleNames []string, pass func(moduleName string) bool) {
	ms := make(map[string]bool)
	for _, m := range moduleNames {
		ms[m] = true
	}
	var missing []string
	for m := range m.Modules {
		m := m
		if pass != nil && pass(m) {
			continue
		}

		if !ms[m] {
			missing = append(missing, m)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		panic(fmt.Sprintf(
			"all modules must be defined when setting %s, missing: %v", setOrderFnName, missing))
	}
}

// MigrationHandler is the migration function that each module registers.
type MigrationHandler func(ctx sdk.Context) error

// VersionMap is a map of moduleName -> version
type VersionMap = appmodule.VersionMap

// RunMigrations performs in-place store migrations for all modules. This
// function MUST be called inside an x/upgrade UpgradeHandler.
//
// Recall that in an upgrade handler, the `fromVM` VersionMap is retrieved from
// x/upgrade's store, and the function needs to return the target VersionMap
// that will in turn be persisted to the x/upgrade's store. In general,
// returning RunMigrations should be enough:
//
// Example:
//
//	cfg := module.NewConfigurator(...)
//	app.UpgradeKeeper.SetUpgradeHandler("my-plan", func(ctx context.Context, plan upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
//	    return app.mm.RunMigrations(ctx, cfg, fromVM)
//	})
//
// Internally, RunMigrations will perform the following steps:
// - create an `updatedVM` VersionMap of module with their latest ConsensusVersion
// - make a diff of `fromVM` and `udpatedVM`, and for each module:
//   - if the module's `fromVM` version is less than its `updatedVM` version,
//     then run in-place store migrations for that module between those versions.
//   - if the module does not exist in the `fromVM` (which means that it's a new module,
//     because it was not in the previous x/upgrade's store), then run
//     `InitGenesis` on that module.
//
// - return the `updatedVM` to be persisted in the x/upgrade's store.
//
// Migrations are run in an order defined by `Manager.OrderMigrations` or (if not set) defined by
// `DefaultMigrationsOrder` function.
//
// As an app developer, if you wish to skip running InitGenesis for your new
// module "foo", you need to manually pass a `fromVM` argument to this function
// foo's module version set to its latest ConsensusVersion. That way, the diff
// between the function's `fromVM` and `udpatedVM` will be empty, hence not
// running anything for foo.
//
// Example:
//
//	cfg := module.NewConfigurator(...)
//	app.UpgradeKeeper.SetUpgradeHandler("my-plan", func(ctx context.Context, plan upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
//	    // Assume "foo" is a new module.
//	    // `fromVM` is fetched from existing x/upgrade store. Since foo didn't exist
//	    // before this upgrade, `v, exists := fromVM["foo"]; exists == false`, and RunMigration will by default
//	    // run InitGenesis on foo.
//	    // To skip running foo's InitGenesis, you need set `fromVM`'s foo to its latest
//	    // consensus version:
//	    fromVM["foo"] = foo.AppModule{}.ConsensusVersion()
//
//	    return app.mm.RunMigrations(ctx, cfg, fromVM)
//	})
//
// Please also refer to https://docs.cosmos.network/main/core/upgrade for more information.
func (m Manager) RunMigrations(ctx context.Context, cfg Configurator, fromVM appmodule.VersionMap) (appmodule.VersionMap, error) {
	c, ok := cfg.(*configurator)
	if !ok {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", &configurator{}, cfg)
	}
	modules := m.OrderMigrations
	if modules == nil {
		modules = DefaultMigrationsOrder(m.ModuleNames())
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	updatedVM := appmodule.VersionMap{}
	for _, moduleName := range modules {
		module := m.Modules[moduleName]
		fromVersion, exists := fromVM[moduleName]
		toVersion := uint64(0)
		if module, ok := module.(appmodule.HasConsensusVersion); ok {
			toVersion = module.ConsensusVersion()
		}

		// We run migration if the module is specified in `fromVM`.
		// Otherwise we run InitGenesis.
		//
		// The module won't exist in the fromVM in two cases:
		// 1. A new module is added. In this case we run InitGenesis with an
		// empty genesis state.
		// 2. An existing chain is upgrading from version < 0.43 to v0.43+ for the first time.
		// In this case, all modules have yet to be added to x/upgrade's VersionMap store.
		if exists {
			err := c.runModuleMigrations(sdkCtx, moduleName, fromVersion, toVersion)
			if err != nil {
				return nil, err
			}
		} else {
			sdkCtx.Logger().Info(fmt.Sprintf("adding a new module: %s", moduleName))
			if module, ok := m.Modules[moduleName].(HasGenesis); ok {
				module.InitGenesis(sdkCtx, c.cdc, module.DefaultGenesis(c.cdc))
			}
			if module, ok := m.Modules[moduleName].(HasABCIGenesis); ok {
				moduleValUpdates := module.InitGenesis(sdkCtx, c.cdc, module.DefaultGenesis(c.cdc))
				// The module manager assumes only one module will update the validator set, and it can't be a new module.
				if len(moduleValUpdates) > 0 {
					return nil, errorsmod.Wrapf(sdkerrors.ErrLogic, "validator InitGenesis update is already set by another module")
				}
			}
		}

		updatedVM[moduleName] = toVersion
	}

	return updatedVM, nil
}

// PreBlock performs begin block functionality for upgrade module.
// It takes the current context as a parameter and returns a boolean value
// indicating whether the migration was successfully executed or not.
func (m *Manager) PreBlock(ctx sdk.Context) (*sdk.ResponsePreBlock, error) {
	ctx = ctx.WithEventManager(sdk.NewEventManager())
	paramsChanged := false
	for _, moduleName := range m.OrderPreBlockers {
		if module, ok := m.Modules[moduleName].(appmodule.HasPreBlocker); ok {
			rsp, err := module.PreBlock(ctx)
			if err != nil {
				return nil, err
			}
			if rsp.IsConsensusParamsChanged() {
				paramsChanged = true
			}
		}
	}
	return &sdk.ResponsePreBlock{
		ConsensusParamsChanged: paramsChanged,
	}, nil
}

// BeginBlock performs begin block functionality for all modules. It creates a
// child context with an event manager to aggregate events emitted from all
// modules.
func (m *Manager) BeginBlock(ctx sdk.Context) (sdk.BeginBlock, error) {
	ctx = ctx.WithEventManager(sdk.NewEventManager())
	for _, moduleName := range m.OrderBeginBlockers {
		if module, ok := m.Modules[moduleName].(appmodule.HasBeginBlocker); ok {
			if err := module.BeginBlock(ctx); err != nil {
				return sdk.BeginBlock{}, err
			}
		}
	}

	return sdk.BeginBlock{
		Events: ctx.EventManager().ABCIEvents(),
	}, nil
}

// EndBlock performs end block functionality for all modules. It creates a
// child context with an event manager to aggregate events emitted from all
// modules.
func (m *Manager) EndBlock(ctx sdk.Context) (sdk.EndBlock, error) {
	ctx = ctx.WithEventManager(sdk.NewEventManager())
	validatorUpdates := []appmodule.ValidatorUpdate{}

	for _, moduleName := range m.OrderEndBlockers {
		if module, ok := m.Modules[moduleName].(appmodule.HasEndBlocker); ok {
			err := module.EndBlock(ctx)
			if err != nil {
				return sdk.EndBlock{}, err
			}
		} else if module, ok := m.Modules[moduleName].(HasABCIEndBlock); ok {
			moduleValUpdates, err := module.EndBlock(ctx)
			if err != nil {
				return sdk.EndBlock{}, err
			}
			// use these validator updates if provided, the module manager assumes
			// only one module will update the validator set
			if len(moduleValUpdates) > 0 {
				if len(validatorUpdates) > 0 {
					return sdk.EndBlock{}, errors.New("validator EndBlock updates already set by a previous module")
				}

				validatorUpdates = append(validatorUpdates, moduleValUpdates...)
			}
		}
	}

	cometValidatorUpdates := make([]abci.ValidatorUpdate, len(validatorUpdates))
	for i, v := range validatorUpdates {
		var pubkey cmtcryptoproto.PublicKey
		switch v.PubKeyType {
		case "ed25519":
			pubkey = cmtcryptoproto.PublicKey{
				Sum: &cmtcryptoproto.PublicKey_Ed25519{
					Ed25519: v.PubKey,
				},
			}
		case "secp256k1":
			pubkey = cmtcryptoproto.PublicKey{
				Sum: &cmtcryptoproto.PublicKey_Secp256K1{
					Secp256K1: v.PubKey,
				},
			}
		}

		cometValidatorUpdates[i] = abci.ValidatorUpdate{
			PubKey: pubkey,
			Power:  v.Power,
		}
	}

	return sdk.EndBlock{
		ValidatorUpdates: cometValidatorUpdates,
		Events:           ctx.EventManager().ABCIEvents(),
	}, nil
}

// Precommit performs precommit functionality for all modules.
func (m *Manager) Precommit(ctx sdk.Context) error {
	for _, moduleName := range m.OrderPrecommiters {
		module, ok := m.Modules[moduleName].(appmodule.HasPrecommit)
		if !ok {
			continue
		}
		if err := module.Precommit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// PrepareCheckState performs functionality for preparing the check state for all modules.
func (m *Manager) PrepareCheckState(ctx sdk.Context) error {
	for _, moduleName := range m.OrderPrepareCheckStaters {
		module, ok := m.Modules[moduleName].(appmodule.HasPrepareCheckState)
		if !ok {
			continue
		}
		if err := module.PrepareCheckState(ctx); err != nil {
			return err
		}
	}
	return nil
}

// GetVersionMap gets consensus version from all modules
func (m *Manager) GetVersionMap() appmodule.VersionMap {
	vermap := make(appmodule.VersionMap)
	for name, v := range m.Modules {
		version := uint64(0)
		if v, ok := v.(appmodule.HasConsensusVersion); ok {
			version = v.ConsensusVersion()
		}
		name := name
		vermap[name] = version
	}

	return vermap
}

// ModuleNames returns list of all module names, without any particular order.
func (m *Manager) ModuleNames() []string {
	return maps.Keys(m.Modules)
}

// DefaultMigrationsOrder returns a default migrations order: ascending alphabetical by module name,
// except x/auth which will run last, see:
// https://github.com/cosmos/cosmos-sdk/issues/10591
func DefaultMigrationsOrder(modules []string) []string {
	const authName = "auth"
	out := make([]string, 0, len(modules))
	hasAuth := false
	for _, m := range modules {
		if m == authName {
			hasAuth = true
		} else {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	if hasAuth {
		out = append(out, authName)
	}
	return out
}
