// SPDX-License-Identifier: CC0-1.0

//! Which resource TYPES a template may declare.
//!
//! ## The rule this module implements
//!
//! CloudFormation deploys only the resource types it KNOWS. A template whose `Resources`
//! section declares a type that is neither one of the resource types Amazon Web Services
//! publishes, nor a custom resource, nor an extension this account activated or
//! registered, is refused when the template is submitted — HTTP 400 with the wire error
//! code `ValidationError` and the recorded message `Template format error: Unrecognized
//! resource types: [<types>]` ([`unrecognized_message`]) — and nothing is created: the
//! stack never reaches `CREATE_IN_PROGRESS`, let alone `CREATE_COMPLETE`.
//!
//! That refusal is the whole point of the check. The dangerous direction for an emulator
//! is the permissive one: a template declaring a type that does not exist (a service's
//! resource CloudFormation has no resource type for at all, a misspelled type, a
//! third-party extension nobody activated) must not deploy here and then be refused in a
//! real account, and a stack that "succeeded" here must not report outputs for a resource
//! no service was ever asked to create.
//!
//! ## What the recognised set is
//!
//! Four disjoint cases, in the order [`is_recognized`] decides them:
//!
//! 1. **A type CloudFormation itself serves** — [`BUILT_IN_RESOURCE_TYPES`]: a type whose
//!    deployment calls no owning service at all, because CloudFormation is the service that
//!    owns it. Such a type is recognised without being registered or activated and without
//!    being published in the resource reference, so it is decided before the catalogue is
//!    consulted.
//! 2. **`AWS::<Namespace>::<Resource>`** — a resource type Amazon Web Services publishes,
//!    which is [`AWS_RESOURCE_TYPES`] below: the catalogue of type names, taken from the
//!    "AWS resource and property types reference" of the CloudFormation User Guide, which
//!    is where the set of types a template may declare is published (the service's Smithy
//!    model enumerates no resource types at all — `smithy_query(query="shape",
//!    shape="ResourceTypes")` is a list of plain `ResourceType` strings). A namespace a
//!    template spells here but that publishes no resource types — Amazon Simple Workflow
//!    Service creates its domains only through its own `RegisterDomain` API — simply has
//!    no entry, which is what makes every type under it unrecognised.
//! 3. **A custom resource** — `Custom::<Name>` ("Custom::*String*. The resource type name
//!    can be up to 60 characters and can include alphanumeric characters and these
//!    characters: `_@-`") or the generic `AWS::CloudFormation::CustomResource`. A custom
//!    resource names no registered type: it is backed by the `ServiceToken` its own
//!    properties carry, so CloudFormation accepts any such name.
//! 4. **Anything else** — `<Org>::<Service>::<Resource>`, a third-party public extension
//!    or a private one — is recognised only once this account's registry holds it, and no
//!    registry WRITER exists yet: `RegisterType`, `ActivateType` and
//!    `PublishType` are all still scaffold stubs with their own issues
//!    (`src/ops/register_type.rs`, `src/ops/activate_type.rs`), so nothing can put such an
//!    extension in [`super::registry`] and a template declaring one is refused. When those
//!    writers land, this is the one place that has to consult the stored registry.
//!
//! The catalogue is NOT the list of types this emulator deploys. A catalogued type with no
//! provisioner is still declared-only (see [`super::provisioning`]), and a catalogued type
//! whose published return values this emulator carries is in
//! [`super::template::IMPLEMENTED_RESOURCE_TYPES`] — a subset of this catalogue. What this
//! module answers is only whether a template may declare the type at all.
//!
//! ## Which operations are held to it
//!
//! The ones that submit a template for DEPLOYMENT: `CreateStack`, `UpdateStack` and
//! `CreateChangeSet`. `ValidateTemplate` is NOT one of them — its documented scope is the
//! body's form ("CloudFormation first checks if the template is valid JSON. If it isn't,
//! CloudFormation checks if the template is valid YAML. If both these checks fail,
//! CloudFormation returns a template validation error"), and a template declaring a type
//! CloudFormation does not recognise is still well-formed JSON or YAML.
//!
//! ## What is NOT held to the catalogue
//!
//! A template that declares a `Transform` this emulator does not process. "CloudFormation
//! processes the template fragments" a macro is given and validates the PROCESSED template,
//! so the types such a template spells may be a macro's input rather than what
//! CloudFormation ends up validating. The familiar case — `AWS::Serverless::*` under the
//! `AWS::Serverless-2016-10-31` transform — IS processed ([`super::sam`] expands it before
//! [`super::template`] reads a resource, so what reaches this catalogue is the concrete
//! types that expansion produced), but every other macro is still unexpanded and
//! [`super::template`] leaves a `Fn::Transform` unevaluated, so holding a transformed
//! template to this catalogue would refuse types the expansion would have produced. Such a
//! template is admitted, and its resources are recorded as declared.

use super::provisioner::redshift_snapshot_copy_grants::REDSHIFT_SNAPSHOT_COPY_GRANT;
use super::provisioner::ssm_maintenance_windows::SSM_MAINTENANCE_WINDOW_TARGET;
use super::template::{
    DeclaredResource, Template, ACMPCA_CERTIFICATE, ACMPCA_CERTIFICATE_AUTHORITY,
    ACMPCA_CERTIFICATE_AUTHORITY_ACTIVATION, ACMPCA_PERMISSION, AMPLIFYUIBUILDER_COMPONENT,
    AMPLIFYUIBUILDER_FORM, AMPLIFYUIBUILDER_THEME, AMPLIFY_APP, AMPLIFY_BRANCH,
    APIGATEWAY_ACCOUNT,
    APIGATEWAY_BASE_PATH_MAPPING, APIGATEWAY_DOMAIN_NAME,
    APPLICATION_SIGNALS_GROUPING_CONFIGURATION, APPLICATION_SIGNALS_INSTRUMENTATION_CONFIG,
    APPLICATION_SIGNALS_SERVICE_LEVEL_OBJECTIVE, BACKUP_GATEWAY_HYPERVISOR,
    BCM_DASHBOARD, BCM_SCHEDULED_REPORT,
    BRAKET_SPENDING_LIMIT,
    CLEANROOMSML_TRAINING_DATASET,
    CLOUDFRONT_CONNECTION_FUNCTION, CLOUDFRONT_CONNECTION_GROUP, CLOUDFRONT_FUNCTION,
    CLOUDFRONT_KEY_VALUE_STORE, CLOUDFRONT_MONITORING_SUBSCRIPTION,
    CUSTOMER_PROFILES_DOMAIN, GLUE_TABLE_OPTIMIZER, MEDIACONVERT_CERTIFICATE_ASSOCIATION,
    MWAA_ENVIRONMENT, NEPTUNE_GRAPH_GRAPH,
    NEPTUNE_GRAPH_GRAPH_SNAPSHOT, RBIN_RULE, SES_EMAIL_IDENTITY,
};

/// The namespace Amazon Web Services' own resource types live under: a type spelled with
/// it is recognised exactly when [`AWS_RESOURCE_TYPES`] carries it.
const AWS_NAMESPACE_PREFIX: &str = "AWS::";

/// The namespace of a custom resource: "Custom::*String*", where the name is the author's
/// own.
const CUSTOM_NAMESPACE_PREFIX: &str = "Custom::";

/// The inert record the AWS Cloud Development Kit writes a synthesized stack's version
/// report into: "the CDK collects…the versions of…libraries used…by adding a resource of
/// type `AWS::CDK::Metadata` to the stack" (AWS CDK Developer Guide, "Version reporting"),
/// whose only property is the `Analytics` string that report is encoded into.
pub const CDK_METADATA: &str = "AWS::CDK::Metadata";

/// The resource types CloudFormation SERVES ITSELF: a deployment of one calls no owning
/// service, so there is nothing to register or activate and the resource reference does not
/// publish it among a service's types.
///
/// `AWS::CDK::Metadata` is one: the CDK adds it to every stack it synthesizes unless version
/// reporting is turned off, and CloudFormation accepts and deploys it in any account, which
/// is what lets a stack the CDK produced deploy at all. There is no resource outside the
/// stack for it to be — the version report IS the resource — so it is left declared-only
/// like a catalogued type this emulator provisions nothing for
/// ([`super::provisioning`]): it is recorded under the type the template declared, reaches
/// the deployment's own terminal resource status, takes an `Analytics` change in place and
/// is removed with the stack.
///
/// A LIST, so a further type CloudFormation serves itself is one entry rather than another
/// branch, and [`is_recognized`] is the one place the case is decided.
pub const BUILT_IN_RESOURCE_TYPES: &[&str] = &[CDK_METADATA];

/// The generic spelling of a custom resource, documented beside `Custom::String`: "The
/// resource type name you specify … `AWS::CloudFormation::CustomResource`".
const CLOUDFORMATION_CUSTOM_RESOURCE: &str = "AWS::CloudFormation::CustomResource";

/// How long a custom resource's own name may be: "The resource type name can be up to 60
/// characters" (custom resource reference, `Custom::String`).
const MAX_CUSTOM_RESOURCE_NAME_CHARS: usize = 60;

/// The non-alphanumeric characters a custom resource's name admits: "can include
/// alphanumeric characters and these characters: `_@-`".
const CUSTOM_RESOURCE_NAME_PUNCTUATION: [char; 3] = ['_', '@', '-'];

/// What CloudFormation prefixes a refusal of the template BODY with, as recorded:
/// `Template format error: Unrecognized resource types: [AWS::SWF::Domain]`.
const TEMPLATE_FORMAT_ERROR_PREFIX: &str = "Template format error: ";

/// The resource types a template may declare under the `AWS::` namespace.
///
/// Source: the "AWS resource and property types reference" in the CloudFormation User
/// Guide, which publishes one page per type under its service's namespace; the entries are
/// grouped by that namespace below and spelled exactly as that reference spells them (an
/// `AWS::ECR::PublicRepository` lives in the `ECR` namespace rather than under the ECR
/// Public model's own `cloudFormationName`, because the type is what a template spells —
/// see [`super::template::ECR_PUBLIC_REPOSITORY`]).
///
/// Lookup is a linear scan over `&'static str`s ([`is_published`]), which is what a
/// template's declarations can afford: a template declares at most
/// [`super::template::MAX_RESOURCES_PER_TEMPLATE`] resources, each checked once per
/// submitted body.
///
/// A namespace with no entry here, and an entry this list does not carry, are both
/// unrecognised — the refusal, not the silence, is the point. Adding a type is a one-line
/// change, and a type this emulator grows a provisioner for must be here before a template
/// can declare it.
///
/// The catalogue is a LIST, so it is only as complete as its entries: a type the reference
/// publishes and this list does not carry is refused, which is the restrictive direction of
/// the same rule. That is the deliberate trade — the permissive direction deploys resources
/// real CloudFormation refuses outright — and the remedy for a missing published type is to
/// add it here, in its namespace's group, rather than to weaken the check to a shape test
/// (`AWS::<anything>::<anything>`), which would admit `AWS::SWF::Domain` again.
pub const AWS_RESOURCE_TYPES: &[&str] = &[
    // Amazon Web Services Private CA. The certificate authority itself, a certificate one
    // of its CAs issues, the activation of a CA with such a certificate and the permission a
    // CA grants to a service principal are all created in the owning service
    // (`super::provisioner`).
    ACMPCA_CERTIFICATE,
    ACMPCA_CERTIFICATE_AUTHORITY,
    ACMPCA_CERTIFICATE_AUTHORITY_ACTIVATION,
    ACMPCA_PERMISSION,
    // Amazon MQ
    "AWS::AmazonMQ::Broker",
    "AWS::AmazonMQ::Configuration",
    "AWS::AmazonMQ::ConfigurationAssociation",
    // AWS Amplify
    AMPLIFY_APP,
    AMPLIFY_BRANCH,
    "AWS::Amplify::Domain",
    // Amplify UI Builder. The three UI entities of an Amplify app environment are each
    // created in that service (`super::provisioner`), which is also where the middle segment
    // of the type name comes from: its model's own `awsService.cloudFormationName`
    // (`AmplifyUIBuilder`), with the resource segment each entity's own `@cfnResource` name.
    AMPLIFYUIBUILDER_COMPONENT,
    AMPLIFYUIBUILDER_FORM,
    AMPLIFYUIBUILDER_THEME,
    // Amazon API Gateway
    APIGATEWAY_ACCOUNT,
    "AWS::ApiGateway::ApiKey",
    "AWS::ApiGateway::Authorizer",
    APIGATEWAY_BASE_PATH_MAPPING,
    "AWS::ApiGateway::ClientCertificate",
    "AWS::ApiGateway::Deployment",
    "AWS::ApiGateway::DocumentationPart",
    "AWS::ApiGateway::DocumentationVersion",
    APIGATEWAY_DOMAIN_NAME,
    "AWS::ApiGateway::GatewayResponse",
    "AWS::ApiGateway::Method",
    "AWS::ApiGateway::Model",
    "AWS::ApiGateway::RequestValidator",
    "AWS::ApiGateway::Resource",
    "AWS::ApiGateway::RestApi",
    "AWS::ApiGateway::Stage",
    "AWS::ApiGateway::UsagePlan",
    "AWS::ApiGateway::UsagePlanKey",
    "AWS::ApiGateway::VpcLink",
    // Amazon API Gateway V2
    "AWS::ApiGatewayV2::Api",
    "AWS::ApiGatewayV2::ApiMapping",
    "AWS::ApiGatewayV2::Authorizer",
    "AWS::ApiGatewayV2::Deployment",
    "AWS::ApiGatewayV2::DomainName",
    "AWS::ApiGatewayV2::Integration",
    "AWS::ApiGatewayV2::IntegrationResponse",
    "AWS::ApiGatewayV2::Model",
    "AWS::ApiGatewayV2::Route",
    "AWS::ApiGatewayV2::RouteResponse",
    "AWS::ApiGatewayV2::Stage",
    "AWS::ApiGatewayV2::VpcLink",
    // AWS AppConfig
    "AWS::AppConfig::Application",
    "AWS::AppConfig::ConfigurationProfile",
    "AWS::AppConfig::Deployment",
    "AWS::AppConfig::DeploymentStrategy",
    "AWS::AppConfig::Environment",
    "AWS::AppConfig::ExperimentDefinition",
    "AWS::AppConfig::Extension",
    "AWS::AppConfig::ExtensionAssociation",
    "AWS::AppConfig::HostedConfigurationVersion",
    // AWS App Mesh
    "AWS::AppMesh::GatewayRoute",
    "AWS::AppMesh::Mesh",
    "AWS::AppMesh::Route",
    "AWS::AppMesh::VirtualGateway",
    "AWS::AppMesh::VirtualNode",
    "AWS::AppMesh::VirtualRouter",
    "AWS::AppMesh::VirtualService",
    // AWS App Runner
    "AWS::AppRunner::AutoScalingConfiguration",
    "AWS::AppRunner::ObservabilityConfiguration",
    "AWS::AppRunner::Service",
    "AWS::AppRunner::VpcConnector",
    // Application Auto Scaling
    "AWS::ApplicationAutoScaling::ScalableTarget",
    "AWS::ApplicationAutoScaling::ScalingPolicy",
    // Amazon CloudWatch Application Insights
    "AWS::ApplicationInsights::Application",
    // Amazon CloudWatch Application Signals. The three types this emulator creates in that
    // service itself (`super::provisioner`): the service level objective its
    // `CreateServiceLevelObjective` makes, the one grouping configuration per account its
    // `PutGroupingConfiguration` keeps, and the dynamic instrumentation point its
    // `CreateInstrumentationConfiguration` records. The namespace's other published types have
    // no entry yet — a catalogued type with no provisioner deploys as declared-only, which
    // would report a stack resource nothing created.
    APPLICATION_SIGNALS_SERVICE_LEVEL_OBJECTIVE,
    APPLICATION_SIGNALS_GROUPING_CONFIGURATION,
    APPLICATION_SIGNALS_INSTRUMENTATION_CONFIG,
    // AWS AppSync
    crate::state::template::APPSYNC_API,
    "AWS::AppSync::ApiKey",
    crate::state::template::APPSYNC_CHANNEL_NAMESPACE,
    "AWS::AppSync::DataSource",
    crate::state::provisioning::appsync_domain_names::APPSYNC_DOMAIN_NAME,
    crate::state::provisioning::appsync_domain_names::APPSYNC_DOMAIN_NAME_API_ASSOCIATION,
    "AWS::AppSync::FunctionConfiguration",
    "AWS::AppSync::GraphQLApi",
    "AWS::AppSync::GraphQLSchema",
    "AWS::AppSync::Resolver",
    crate::state::template::APPSYNC_SOURCE_API_ASSOCIATION,
    // Amazon Athena
    "AWS::Athena::DataCatalog",
    "AWS::Athena::NamedQuery",
    "AWS::Athena::WorkGroup",
    // Amazon EC2 Auto Scaling
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::AutoScaling::LaunchConfiguration",
    "AWS::AutoScaling::LifecycleHook",
    "AWS::AutoScaling::ScalingPolicy",
    "AWS::AutoScaling::ScheduledAction",
    "AWS::AutoScaling::WarmPool",
    // AWS Backup
    "AWS::Backup::BackupPlan",
    "AWS::Backup::BackupSelection",
    "AWS::Backup::BackupVault",
    // AWS Backup Gateway. A hypervisor is the on-premises host that service's own
    // `ImportHypervisorConfiguration` connects to, which `super::provisioner` imports there.
    BACKUP_GATEWAY_HYPERVISOR,
    // AWS Batch
    "AWS::Batch::ComputeEnvironment",
    "AWS::Batch::ConsumableResource",
    "AWS::Batch::JobDefinition",
    "AWS::Batch::JobQueue",
    "AWS::Batch::QuotaShare",
    "AWS::Batch::SchedulingPolicy",
    "AWS::Batch::ServiceEnvironment",
    // Billing and Cost Management Dashboards. The dashboard and the scheduled report on one
    // are both created in the owning service (`super::provisioner`): `CreateDashboard` and
    // `CreateScheduledReport`.
    BCM_DASHBOARD,
    BCM_SCHEDULED_REPORT,
    // Amazon Bedrock
    "AWS::Bedrock::Agent",
    "AWS::Bedrock::AgentAlias",
    "AWS::Bedrock::DataSource",
    "AWS::Bedrock::Flow",
    "AWS::Bedrock::Guardrail",
    "AWS::Bedrock::KnowledgeBase",
    // Amazon Bedrock AgentCore — the six types this emulator carries the published return
    // values of (`super::template::IMPLEMENTED_RESOURCE_TYPES`).
    "AWS::BedrockAgentCore::Browser",
    "AWS::BedrockAgentCore::CodeInterpreter",
    "AWS::BedrockAgentCore::Gateway",
    "AWS::BedrockAgentCore::Memory",
    "AWS::BedrockAgentCore::Runtime",
    "AWS::BedrockAgentCore::WorkloadIdentity",
    // Amazon Braket. A spending limit is the cost control that service's own
    // `CreateSpendingLimit` makes for a quantum device, which `super::provisioner` creates
    // there.
    BRAKET_SPENDING_LIMIT,
    // AWS Budgets
    "AWS::Budgets::Budget",
    // Amazon Keyspaces (for Apache Cassandra)
    "AWS::Cassandra::Keyspace",
    "AWS::Cassandra::Table",
    // AWS Cost Explorer
    "AWS::CE::AnomalyMonitor",
    "AWS::CE::AnomalySubscription",
    // AWS Certificate Manager
    "AWS::CertificateManager::Account",
    "AWS::CertificateManager::AcmeEndpoint",
    "AWS::CertificateManager::Certificate",
    // Clean Rooms ML. A training dataset is the metadata record that service's own
    // `CreateTrainingDataset` makes for a Glue table, which `super::provisioner` creates
    // there. (The other published types of this namespace, and the AWS::CleanRooms ones
    // beside them, are not here yet: a catalogued type with no provisioner would deploy as
    // declared-only, and a client that deployed one would read nothing back from the service
    // that is supposed to own it.)
    CLEANROOMSML_TRAINING_DATASET,
    // AWS CloudFormation's own types, including the generic custom resource and the
    // registry's own records.
    CLOUDFORMATION_CUSTOM_RESOURCE,
    // The two Hook types a template may declare a Hook itself with, beside the registry
    // records below: a Guard Hook, which evaluates CloudFormation Guard rules against a
    // stack operation's targets, and a Lambda Hook, which hands those targets to a function
    // (the two Hook kinds the CloudFormation Hooks documentation publishes, and the two this
    // registry's own public catalogue holds —
    // [`crate::state::registry::PUBLIC_EXTENSION_CATALOG`]).
    "AWS::CloudFormation::GuardHook",
    "AWS::CloudFormation::HookDefaultVersion",
    "AWS::CloudFormation::HookTypeConfig",
    "AWS::CloudFormation::HookVersion",
    "AWS::CloudFormation::LambdaHook",
    "AWS::CloudFormation::Macro",
    "AWS::CloudFormation::ModuleDefaultVersion",
    "AWS::CloudFormation::ModuleVersion",
    "AWS::CloudFormation::PublicTypeVersion",
    "AWS::CloudFormation::Publisher",
    "AWS::CloudFormation::ResourceDefaultVersion",
    "AWS::CloudFormation::ResourceVersion",
    "AWS::CloudFormation::Stack",
    "AWS::CloudFormation::StackSet",
    "AWS::CloudFormation::TypeActivation",
    "AWS::CloudFormation::WaitCondition",
    "AWS::CloudFormation::WaitConditionHandle",
    // Amazon CloudFront
    "AWS::CloudFront::CachePolicy",
    "AWS::CloudFront::CloudFrontOriginAccessIdentity",
    CLOUDFRONT_CONNECTION_FUNCTION,
    CLOUDFRONT_CONNECTION_GROUP,
    "AWS::CloudFront::Distribution",
    CLOUDFRONT_FUNCTION,
    "AWS::CloudFront::KeyGroup",
    CLOUDFRONT_KEY_VALUE_STORE,
    CLOUDFRONT_MONITORING_SUBSCRIPTION,
    "AWS::CloudFront::OriginAccessControl",
    "AWS::CloudFront::OriginRequestPolicy",
    "AWS::CloudFront::PublicKey",
    "AWS::CloudFront::ResponseHeadersPolicy",
    // AWS CloudTrail
    "AWS::CloudTrail::EventDataStore",
    "AWS::CloudTrail::Trail",
    // Amazon CloudWatch
    "AWS::CloudWatch::Alarm",
    "AWS::CloudWatch::AnomalyDetector",
    "AWS::CloudWatch::CompositeAlarm",
    "AWS::CloudWatch::Dashboard",
    "AWS::CloudWatch::MetricStream",
    // AWS CodeArtifact
    "AWS::CodeArtifact::Domain",
    "AWS::CodeArtifact::Repository",
    // AWS CodeBuild
    "AWS::CodeBuild::Project",
    "AWS::CodeBuild::ReportGroup",
    "AWS::CodeBuild::SourceCredential",
    // AWS CodeCommit
    "AWS::CodeCommit::Repository",
    // AWS CodeDeploy
    "AWS::CodeDeploy::Application",
    "AWS::CodeDeploy::DeploymentConfig",
    "AWS::CodeDeploy::DeploymentGroup",
    // AWS CodePipeline
    "AWS::CodePipeline::CustomActionType",
    "AWS::CodePipeline::Pipeline",
    "AWS::CodePipeline::Webhook",
    // Amazon Cognito: the whole published group. Each entry is followed by the operation
    // of the owning service's own model in this checkout that deploying it calls — the
    // cross-check that the type names a resource one of the two Amazon Cognito APIs really
    // creates (`cognito-identity` for the three identity-pool types, `cognito-idp` for the
    // user-pool ones).
    "AWS::Cognito::IdentityPool", // CreateIdentityPool
    "AWS::Cognito::IdentityPoolPrincipalTag", // SetPrincipalTagAttributeMap
    "AWS::Cognito::IdentityPoolRoleAttachment", // SetIdentityPoolRoles
    "AWS::Cognito::LogDeliveryConfiguration", // SetLogDeliveryConfiguration
    "AWS::Cognito::ManagedLoginBranding", // CreateManagedLoginBranding
    "AWS::Cognito::UserPool",       // CreateUserPool
    "AWS::Cognito::UserPoolClient", // CreateUserPoolClient
    "AWS::Cognito::UserPoolDomain", // CreateUserPoolDomain
    "AWS::Cognito::UserPoolGroup",  // CreateGroup
    "AWS::Cognito::UserPoolIdentityProvider", // CreateIdentityProvider
    "AWS::Cognito::UserPoolResourceServer", // CreateResourceServer
    "AWS::Cognito::UserPoolRiskConfigurationAttachment", // SetRiskConfiguration
    "AWS::Cognito::UserPoolUICustomizationAttachment", // SetUICustomization
    "AWS::Cognito::UserPoolUser",   // AdminCreateUser
    "AWS::Cognito::UserPoolUserToGroupAttachment", // AdminAddUserToGroup
    // Amazon Connect
    "AWS::Connect::ContactFlow",
    "AWS::Connect::HoursOfOperation",
    "AWS::Connect::Instance",
    "AWS::Connect::Queue",
    "AWS::Connect::QuickConnect",
    "AWS::Connect::RoutingProfile",
    "AWS::Connect::User",
    "AWS::Connect::UserHierarchyGroup",
    // AWS Config
    "AWS::Config::AggregationAuthorization",
    "AWS::Config::ConfigRule",
    "AWS::Config::ConfigurationAggregator",
    "AWS::Config::ConfigurationRecorder",
    "AWS::Config::ConformancePack",
    "AWS::Config::DeliveryChannel",
    // Amazon Connect Customer Profiles. The DOMAIN is the container every other resource of
    // that service hangs off, and it is created in the owning service
    // (`super::provisioner`): `CreateDomain` POST /domains/{DomainName}. The namespace's
    // other published types have no entry yet — a catalogued type with no provisioner deploys
    // as declared-only, which would report a stack resource nothing created.
    CUSTOMER_PROFILES_DOMAIN, // CreateDomain
    // AWS Glue DataBrew
    "AWS::DataBrew::Dataset",
    "AWS::DataBrew::Job",
    "AWS::DataBrew::Project",
    "AWS::DataBrew::Recipe",
    "AWS::DataBrew::Ruleset",
    "AWS::DataBrew::Schedule",
    // AWS DataSync
    "AWS::DataSync::Agent",
    "AWS::DataSync::LocationEFS",
    "AWS::DataSync::LocationFSxWindows",
    "AWS::DataSync::LocationNFS",
    "AWS::DataSync::LocationS3",
    "AWS::DataSync::LocationSMB",
    "AWS::DataSync::Task",
    // Amazon DynamoDB Accelerator
    "AWS::DAX::Cluster",
    "AWS::DAX::ParameterGroup",
    "AWS::DAX::SubnetGroup",
    // Amazon Detective
    "AWS::Detective::Graph",
    "AWS::Detective::MemberInvitation",
    // AWS Database Migration Service
    "AWS::DMS::Certificate",
    "AWS::DMS::Endpoint",
    "AWS::DMS::EventSubscription",
    "AWS::DMS::ReplicationInstance",
    "AWS::DMS::ReplicationSubnetGroup",
    "AWS::DMS::ReplicationTask",
    // Amazon DocumentDB
    "AWS::DocDB::DBCluster",
    "AWS::DocDB::DBClusterParameterGroup",
    "AWS::DocDB::DBInstance",
    "AWS::DocDB::DBSubnetGroup",
    // Amazon DynamoDB
    "AWS::DynamoDB::GlobalTable",
    "AWS::DynamoDB::Table",
    // Amazon EC2
    "AWS::EC2::CustomerGateway",
    "AWS::EC2::DHCPOptions",
    "AWS::EC2::EC2Fleet",
    "AWS::EC2::EIP",
    "AWS::EC2::EIPAssociation",
    "AWS::EC2::EgressOnlyInternetGateway",
    "AWS::EC2::FlowLog",
    "AWS::EC2::Host",
    "AWS::EC2::Instance",
    "AWS::EC2::InternetGateway",
    "AWS::EC2::KeyPair",
    "AWS::EC2::LaunchTemplate",
    "AWS::EC2::NatGateway",
    "AWS::EC2::NetworkAcl",
    "AWS::EC2::NetworkAclEntry",
    "AWS::EC2::NetworkInterface",
    "AWS::EC2::NetworkInterfaceAttachment",
    "AWS::EC2::PlacementGroup",
    "AWS::EC2::PrefixList",
    "AWS::EC2::Route",
    "AWS::EC2::RouteTable",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::SecurityGroupEgress",
    "AWS::EC2::SecurityGroupIngress",
    "AWS::EC2::SpotFleet",
    "AWS::EC2::Subnet",
    "AWS::EC2::SubnetNetworkAclAssociation",
    "AWS::EC2::SubnetRouteTableAssociation",
    "AWS::EC2::TransitGateway",
    "AWS::EC2::TransitGatewayAttachment",
    "AWS::EC2::TransitGatewayRoute",
    "AWS::EC2::TransitGatewayRouteTable",
    "AWS::EC2::VPC",
    "AWS::EC2::VPCCidrBlock",
    "AWS::EC2::VPCDHCPOptionsAssociation",
    "AWS::EC2::VPCEndpoint",
    "AWS::EC2::VPCEndpointService",
    "AWS::EC2::VPCGatewayAttachment",
    "AWS::EC2::VPCPeeringConnection",
    "AWS::EC2::VPNConnection",
    "AWS::EC2::VPNGateway",
    "AWS::EC2::Volume",
    "AWS::EC2::VolumeAttachment",
    // Amazon ECR, private registry and public gallery
    "AWS::ECR::PublicRepository",
    "AWS::ECR::PullThroughCacheRule",
    "AWS::ECR::RegistryPolicy",
    "AWS::ECR::ReplicationConfiguration",
    "AWS::ECR::Repository",
    // Amazon ECS
    "AWS::ECS::CapacityProvider",
    "AWS::ECS::Cluster",
    "AWS::ECS::ClusterCapacityProviderAssociations",
    "AWS::ECS::PrimaryTaskSet",
    "AWS::ECS::Service",
    "AWS::ECS::TaskDefinition",
    "AWS::ECS::TaskSet",
    // Amazon EFS
    "AWS::EFS::AccessPoint",
    "AWS::EFS::FileSystem",
    "AWS::EFS::MountTarget",
    // Amazon EKS
    "AWS::EKS::AccessEntry",
    "AWS::EKS::Addon",
    "AWS::EKS::Cluster",
    "AWS::EKS::FargateProfile",
    "AWS::EKS::IdentityProviderConfig",
    "AWS::EKS::Nodegroup",
    "AWS::EKS::PodIdentityAssociation",
    // Amazon EMR
    "AWS::EMR::Cluster",
    "AWS::EMR::InstanceFleetConfig",
    "AWS::EMR::InstanceGroupConfig",
    "AWS::EMR::SecurityConfiguration",
    "AWS::EMR::Step",
    "AWS::EMR::Studio",
    "AWS::EMR::StudioSessionMapping",
    // Amazon EMR Serverless
    "AWS::EMRServerless::Application",
    // Amazon ElastiCache
    "AWS::ElastiCache::CacheCluster",
    "AWS::ElastiCache::ParameterGroup",
    "AWS::ElastiCache::ReplicationGroup",
    "AWS::ElastiCache::SecurityGroup",
    "AWS::ElastiCache::ServerlessCache",
    "AWS::ElastiCache::SubnetGroup",
    "AWS::ElastiCache::User",
    "AWS::ElastiCache::UserGroup",
    // AWS Elastic Beanstalk
    "AWS::ElasticBeanstalk::Application",
    "AWS::ElasticBeanstalk::ApplicationVersion",
    "AWS::ElasticBeanstalk::ConfigurationTemplate",
    "AWS::ElasticBeanstalk::Environment",
    // Elastic Load Balancing, classic and v2
    "AWS::ElasticLoadBalancing::LoadBalancer",
    "AWS::ElasticLoadBalancingV2::Listener",
    "AWS::ElasticLoadBalancingV2::ListenerCertificate",
    "AWS::ElasticLoadBalancingV2::ListenerRule",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ElasticLoadBalancingV2::TargetGroup",
    "AWS::ElasticLoadBalancingV2::TrustStore",
    // Amazon OpenSearch Service's predecessor
    "AWS::Elasticsearch::Domain",
    // Amazon EventBridge
    "AWS::Events::ApiDestination",
    "AWS::Events::Archive",
    "AWS::Events::Connection",
    "AWS::Events::EventBus",
    "AWS::Events::EventBusPolicy",
    "AWS::Events::Rule",
    // AWS Fault Injection Service
    "AWS::FIS::ExperimentTemplate",
    // Amazon FSx
    "AWS::FSx::FileSystem",
    // AWS Global Accelerator
    "AWS::GlobalAccelerator::Accelerator",
    "AWS::GlobalAccelerator::EndpointGroup",
    "AWS::GlobalAccelerator::Listener",
    // AWS Glue
    "AWS::Glue::Classifier",
    "AWS::Glue::Connection",
    "AWS::Glue::Crawler",
    "AWS::Glue::Database",
    "AWS::Glue::Job",
    "AWS::Glue::Partition",
    "AWS::Glue::Registry",
    "AWS::Glue::Schema",
    "AWS::Glue::SecurityConfiguration",
    "AWS::Glue::Table",
    // The optimizer of one of those tables, created in AWS Glue itself
    // (`super::provisioner`): the compaction, retention or orphan-file-deletion optimizer a
    // template declares on an open-table-format table.
    GLUE_TABLE_OPTIMIZER,
    "AWS::Glue::Trigger",
    "AWS::Glue::Workflow",
    // Amazon Managed Grafana — the type a workspace is declared as
    // (`super::provisioner` creates it in that service).
    "AWS::Grafana::Workspace",
    // Amazon GuardDuty
    "AWS::GuardDuty::Detector",
    "AWS::GuardDuty::Filter",
    "AWS::GuardDuty::IPSet",
    "AWS::GuardDuty::Master",
    "AWS::GuardDuty::Member",
    "AWS::GuardDuty::ThreatIntelSet",
    // AWS IAM — the catalogue the capability rule draws on too
    // (`super::template::required_capabilities`).
    "AWS::IAM::AccessKey",
    "AWS::IAM::Group",
    "AWS::IAM::GroupPolicy",
    "AWS::IAM::InstanceProfile",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::OIDCProvider",
    "AWS::IAM::Policy",
    "AWS::IAM::Role",
    "AWS::IAM::RolePolicy",
    "AWS::IAM::SAMLProvider",
    "AWS::IAM::ServerCertificate",
    "AWS::IAM::ServiceLinkedRole",
    "AWS::IAM::User",
    "AWS::IAM::UserPolicy",
    "AWS::IAM::UserToGroupAddition",
    "AWS::IAM::VirtualMFADevice",
    // AWS IoT
    "AWS::IoT::Authorizer",
    "AWS::IoT::Certificate",
    "AWS::IoT::Policy",
    "AWS::IoT::PolicyPrincipalAttachment",
    "AWS::IoT::ProvisioningTemplate",
    "AWS::IoT::RoleAlias",
    "AWS::IoT::Thing",
    "AWS::IoT::ThingPrincipalAttachment",
    "AWS::IoT::TopicRule",
    // AWS Key Management Service
    "AWS::KMS::Alias",
    "AWS::KMS::Key",
    "AWS::KMS::ReplicaKey",
    // Amazon Interactive Video Service
    "AWS::IVS::Channel",
    "AWS::IVS::PlaybackKeyPair",
    "AWS::IVS::RecordingConfiguration",
    "AWS::IVS::StreamKey",
    // Amazon Kendra
    "AWS::Kendra::DataSource",
    "AWS::Kendra::Faq",
    "AWS::Kendra::Index",
    // Amazon Kinesis Data Streams and Managed Service for Apache Flink
    "AWS::Kinesis::Stream",
    "AWS::Kinesis::StreamConsumer",
    "AWS::KinesisAnalyticsV2::Application",
    // Amazon Data Firehose
    "AWS::KinesisFirehose::DeliveryStream",
    // AWS Lake Formation
    "AWS::LakeFormation::DataLakeSettings",
    "AWS::LakeFormation::Permissions",
    "AWS::LakeFormation::PrincipalPermissions",
    "AWS::LakeFormation::Resource",
    // AWS Lambda
    "AWS::Lambda::Alias",
    "AWS::Lambda::CodeSigningConfig",
    "AWS::Lambda::EventInvokeConfig",
    "AWS::Lambda::EventSourceMapping",
    "AWS::Lambda::Function",
    "AWS::Lambda::LayerVersion",
    "AWS::Lambda::LayerVersionPermission",
    "AWS::Lambda::Permission",
    "AWS::Lambda::Url",
    "AWS::Lambda::Version",
    // Amazon Lex
    "AWS::Lex::Bot",
    "AWS::Lex::BotAlias",
    "AWS::Lex::BotVersion",
    "AWS::Lex::ResourcePolicy",
    // Amazon Location Service
    "AWS::Location::GeofenceCollection",
    "AWS::Location::Map",
    "AWS::Location::PlaceIndex",
    "AWS::Location::RouteCalculator",
    "AWS::Location::Tracker",
    // Amazon CloudWatch Logs
    "AWS::Logs::Destination",
    "AWS::Logs::LogGroup",
    "AWS::Logs::LogStream",
    "AWS::Logs::MetricFilter",
    "AWS::Logs::QueryDefinition",
    "AWS::Logs::ResourcePolicy",
    "AWS::Logs::SubscriptionFilter",
    // Amazon MSK
    "AWS::MSK::BatchScramSecret",
    "AWS::MSK::Cluster",
    "AWS::MSK::ClusterPolicy",
    "AWS::MSK::Configuration",
    "AWS::MSK::Replicator",
    "AWS::MSK::ServerlessCluster",
    "AWS::MSK::VpcConnection",
    // Amazon Managed Workflows for Apache Airflow. The environment itself is created in the
    // owning service (`super::provisioner`), which is the one resource type that namespace
    // publishes.
    MWAA_ENVIRONMENT,
    // Amazon Macie
    "AWS::Macie::AllowList",
    "AWS::Macie::CustomDataIdentifier",
    "AWS::Macie::FindingsFilter",
    "AWS::Macie::Session",
    // AWS Elemental MediaConvert, MediaLive and MediaPackage. The certificate association
    // is the trust between an ACM certificate and the account's MediaConvert service, made
    // in the owning service (`super::provisioner`).
    MEDIACONVERT_CERTIFICATE_ASSOCIATION,
    "AWS::MediaConvert::JobTemplate",
    "AWS::MediaConvert::Preset",
    "AWS::MediaConvert::Queue",
    "AWS::MediaLive::Channel",
    "AWS::MediaLive::Input",
    "AWS::MediaLive::InputSecurityGroup",
    "AWS::MediaPackage::Channel",
    "AWS::MediaPackage::OriginEndpoint",
    // Amazon MemoryDB
    "AWS::MemoryDB::ACL",
    "AWS::MemoryDB::Cluster",
    "AWS::MemoryDB::ParameterGroup",
    "AWS::MemoryDB::SubnetGroup",
    "AWS::MemoryDB::User",
    // Amazon Neptune
    "AWS::Neptune::DBCluster",
    "AWS::Neptune::DBClusterParameterGroup",
    "AWS::Neptune::DBInstance",
    "AWS::Neptune::DBParameterGroup",
    "AWS::Neptune::DBSubnetGroup",
    // Neptune Analytics — a different service from Amazon Neptune above, reached by the
    // `neptune-graph` signing name. Both types are created in the owning service
    // (`super::provisioner`): `CreateGraph` POST /graphs and `CreateGraphSnapshot` POST
    // /snapshots.
    NEPTUNE_GRAPH_GRAPH,          // CreateGraph
    NEPTUNE_GRAPH_GRAPH_SNAPSHOT, // CreateGraphSnapshot
    // AWS Network Firewall
    "AWS::NetworkFirewall::Firewall",
    "AWS::NetworkFirewall::FirewallPolicy",
    "AWS::NetworkFirewall::LoggingConfiguration",
    "AWS::NetworkFirewall::RuleGroup",
    // AWS Network Manager
    "AWS::NetworkManager::Device",
    "AWS::NetworkManager::GlobalNetwork",
    "AWS::NetworkManager::Link",
    "AWS::NetworkManager::Site",
    // Amazon OpenSearch Serverless
    "AWS::OpenSearchServerless::AccessPolicy",
    "AWS::OpenSearchServerless::Collection",
    "AWS::OpenSearchServerless::SecurityConfig",
    "AWS::OpenSearchServerless::SecurityPolicy",
    "AWS::OpenSearchServerless::VpcEndpoint",
    // Amazon OpenSearch Service
    "AWS::OpenSearchService::Domain",
    // AWS Organizations
    "AWS::Organizations::Account",
    "AWS::Organizations::Organization",
    "AWS::Organizations::OrganizationalUnit",
    "AWS::Organizations::Policy",
    // Amazon Personalize
    "AWS::Personalize::Dataset",
    "AWS::Personalize::DatasetGroup",
    "AWS::Personalize::Schema",
    "AWS::Personalize::Solution",
    // Amazon Pinpoint
    "AWS::Pinpoint::App",
    "AWS::Pinpoint::Campaign",
    "AWS::Pinpoint::Segment",
    // Amazon EventBridge Pipes
    "AWS::Pipes::Pipe",
    // Amazon QLDB
    "AWS::QLDB::Ledger",
    "AWS::QLDB::Stream",
    // Amazon QuickSight
    "AWS::QuickSight::Analysis",
    "AWS::QuickSight::Dashboard",
    "AWS::QuickSight::DataSet",
    "AWS::QuickSight::DataSource",
    "AWS::QuickSight::Template",
    "AWS::QuickSight::Theme",
    // AWS Resource Access Manager
    "AWS::RAM::ResourceShare",
    // Amazon RDS
    "AWS::RDS::DBCluster",
    "AWS::RDS::DBClusterParameterGroup",
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBParameterGroup",
    "AWS::RDS::DBProxy",
    "AWS::RDS::DBProxyTargetGroup",
    "AWS::RDS::DBSecurityGroup",
    "AWS::RDS::DBSubnetGroup",
    "AWS::RDS::EventSubscription",
    "AWS::RDS::GlobalCluster",
    "AWS::RDS::OptionGroup",
    // Amazon CloudWatch RUM
    "AWS::RUM::AppMonitor",
    // Recycle Bin. The retention rule is created in the owning service
    // (`super::provisioner`), through that service's own `CreateRule`.
    RBIN_RULE,
    // Amazon Redshift. The snapshot copy grant is created in the owning service
    // (`super::provisioner`), through that service's own `CreateSnapshotCopyGrant`.
    "AWS::Redshift::Cluster",
    "AWS::Redshift::ClusterParameterGroup",
    "AWS::Redshift::ClusterSecurityGroup",
    "AWS::Redshift::ClusterSubnetGroup",
    REDSHIFT_SNAPSHOT_COPY_GRANT,
    // Amazon Rekognition
    "AWS::Rekognition::Collection",
    "AWS::Rekognition::Project",
    "AWS::Rekognition::StreamProcessor",
    // AWS Resource Groups
    "AWS::ResourceGroups::Group",
    // Amazon Route 53 and Route 53 Resolver
    "AWS::Route53::CidrCollection",
    "AWS::Route53::DelegationSet",
    "AWS::Route53::HealthCheck",
    "AWS::Route53::HostedZone",
    "AWS::Route53::KeySigningKey",
    "AWS::Route53::RecordSet",
    "AWS::Route53::RecordSetGroup",
    "AWS::Route53::TrafficPolicy",
    "AWS::Route53Resolver::FirewallDomainList",
    "AWS::Route53Resolver::FirewallRuleGroup",
    "AWS::Route53Resolver::FirewallRuleGroupAssociation",
    "AWS::Route53Resolver::ResolverEndpoint",
    "AWS::Route53Resolver::ResolverRule",
    "AWS::Route53Resolver::ResolverRuleAssociation",
    // Amazon S3
    "AWS::S3::AccessPoint",
    "AWS::S3::Bucket",
    "AWS::S3::BucketPolicy",
    "AWS::S3::MultiRegionAccessPoint",
    "AWS::S3::StorageLens",
    // Amazon S3 Tables
    "AWS::S3Tables::Namespace",
    "AWS::S3Tables::Table",
    "AWS::S3Tables::TableBucket",
    "AWS::S3Tables::TableBucketPolicy",
    "AWS::S3Tables::TablePolicy",
    // Amazon S3 Vectors, whose namespace segment is that model's own sdk identity
    // (`smithy_query(query="service_info",
    // model_path="services/service-com-amazonaws-s3vectors-s3vectors/smithy-model/\
    // com-amazonaws-s3vectors-s3vectors.json")`: `sdkId: S3Vectors`,
    // `arnNamespace: s3vectors`), beside the sibling bucket variants above.
    "AWS::S3Vectors::Index",
    "AWS::S3Vectors::VectorBucket",
    // Amazon SES
    "AWS::SES::ConfigurationSet",
    // The email identity is created in the owning service (`super::provisioner`), through
    // that service's own `CreateEmailIdentity`.
    SES_EMAIL_IDENTITY,
    "AWS::SES::ReceiptRule",
    "AWS::SES::ReceiptRuleSet",
    "AWS::SES::Template",
    // Amazon SNS
    "AWS::SNS::Subscription",
    "AWS::SNS::Topic",
    // The two types that carry a topic's access policy: the one that applies a document to
    // a list of topics, and the one that belongs to a single topic (`TopicArn` plus
    // `PolicyDocument`), which the resource reference publishes beside it.
    "AWS::SNS::TopicInlinePolicy",
    "AWS::SNS::TopicPolicy",
    // Amazon SQS
    "AWS::SQS::Queue",
    // The two types that carry a queue's access policy: the one that applies a document to
    // a list of queues, and the one that belongs to a single queue (`Queue` plus
    // `PolicyDocument`), which the resource reference publishes beside it.
    "AWS::SQS::QueueInlinePolicy",
    "AWS::SQS::QueuePolicy",
    // AWS Systems Manager
    "AWS::SSM::Association",
    "AWS::SSM::Document",
    "AWS::SSM::MaintenanceWindow",
    // The target a maintenance window's tasks run against, which the resource reference
    // publishes beside the window itself and which this emulator registers in that service
    // (`super::provisioner::ssm_maintenance_windows`).
    SSM_MAINTENANCE_WINDOW_TARGET,
    "AWS::SSM::Parameter",
    "AWS::SSM::PatchBaseline",
    "AWS::SSM::ResourceDataSync",
    // Amazon SageMaker AI
    "AWS::SageMaker::Domain",
    "AWS::SageMaker::Endpoint",
    "AWS::SageMaker::EndpointConfig",
    "AWS::SageMaker::Model",
    "AWS::SageMaker::ModelPackageGroup",
    "AWS::SageMaker::NotebookInstance",
    // The `OnCreate`/`OnStart` shell scripts a notebook instance's `LifecycleConfigName`
    // names, which the resource reference publishes beside the instance itself.
    "AWS::SageMaker::NotebookInstanceLifecycleConfig",
    "AWS::SageMaker::Pipeline",
    "AWS::SageMaker::UserProfile",
    // Amazon EventBridge Scheduler
    "AWS::Scheduler::Schedule",
    "AWS::Scheduler::ScheduleGroup",
    // AWS Secrets Manager
    "AWS::SecretsManager::ResourcePolicy",
    "AWS::SecretsManager::RotationSchedule",
    "AWS::SecretsManager::Secret",
    "AWS::SecretsManager::SecretTargetAttachment",
    // AWS Security Hub
    "AWS::SecurityHub::Hub",
    // AWS Serverless Application Model: the types the `AWS::Serverless-2016-10-31`
    // transform expands. Catalogued because a SAM template declares them directly.
    "AWS::Serverless::Api",
    "AWS::Serverless::Application",
    "AWS::Serverless::Function",
    "AWS::Serverless::HttpApi",
    "AWS::Serverless::LayerVersion",
    "AWS::Serverless::SimpleTable",
    "AWS::Serverless::StateMachine",
    // AWS Service Catalog
    "AWS::ServiceCatalog::CloudFormationProduct",
    "AWS::ServiceCatalog::Portfolio",
    "AWS::ServiceCatalog::PortfolioProductAssociation",
    // AWS Service Catalog AppRegistry
    "AWS::ServiceCatalogAppRegistry::Application",
    "AWS::ServiceCatalogAppRegistry::AttributeGroup",
    // AWS Cloud Map
    "AWS::ServiceDiscovery::HttpNamespace",
    "AWS::ServiceDiscovery::Instance",
    "AWS::ServiceDiscovery::PrivateDnsNamespace",
    "AWS::ServiceDiscovery::PublicDnsNamespace",
    "AWS::ServiceDiscovery::Service",
    // AWS Shield Advanced
    "AWS::Shield::Protection",
    "AWS::Shield::ProtectionGroup",
    // AWS Signer
    "AWS::Signer::ProfilePermission",
    "AWS::Signer::SigningProfile",
    // AWS IAM Identity Center
    "AWS::SSO::Assignment",
    "AWS::SSO::InstanceAccessControlAttributeConfiguration",
    "AWS::SSO::PermissionSet",
    // AWS Step Functions
    "AWS::StepFunctions::Activity",
    "AWS::StepFunctions::StateMachine",
    "AWS::StepFunctions::StateMachineAlias",
    "AWS::StepFunctions::StateMachineVersion",
    // Amazon CloudWatch Synthetics
    "AWS::Synthetics::Canary",
    "AWS::Synthetics::Group",
    // Amazon Timestream
    "AWS::Timestream::Database",
    "AWS::Timestream::Table",
    // AWS Transfer Family
    "AWS::Transfer::Agreement",
    "AWS::Transfer::Certificate",
    "AWS::Transfer::Connector",
    "AWS::Transfer::Profile",
    "AWS::Transfer::Server",
    "AWS::Transfer::User",
    "AWS::Transfer::Workflow",
    // Amazon VPC Lattice
    "AWS::VpcLattice::Listener",
    "AWS::VpcLattice::Service",
    "AWS::VpcLattice::ServiceNetwork",
    "AWS::VpcLattice::TargetGroup",
    // AWS WAF classic (global)
    "AWS::WAF::ByteMatchSet",
    "AWS::WAF::IPSet",
    "AWS::WAF::Rule",
    "AWS::WAF::SizeConstraintSet",
    "AWS::WAF::SqlInjectionMatchSet",
    "AWS::WAF::WebACL",
    "AWS::WAF::XssMatchSet",
    // AWS WAF classic for regional resources, whose own model carries
    // `cloudFormationName: WAFRegional` (`smithy_query(query="service_info",
    // model_path="services/service-com-amazonaws-wafregional-awswaf-regional-20161128/\
    // smithy-model/com-amazonaws-wafregional-awswaf-regional-20161128.json")`). The
    // regional service publishes the four types the global one does not: a geo match set,
    // a rate-based rule, a regex pattern set and the association of a web ACL with a
    // regional resource.
    "AWS::WAFRegional::ByteMatchSet",
    "AWS::WAFRegional::GeoMatchSet",
    "AWS::WAFRegional::IPSet",
    "AWS::WAFRegional::RateBasedRule",
    "AWS::WAFRegional::RegexPatternSet",
    "AWS::WAFRegional::Rule",
    "AWS::WAFRegional::SizeConstraintSet",
    "AWS::WAFRegional::SqlInjectionMatchSet",
    "AWS::WAFRegional::WebACL",
    "AWS::WAFRegional::WebACLAssociation",
    "AWS::WAFRegional::XssMatchSet",
    // AWS WAF v2
    "AWS::WAFv2::IPSet",
    "AWS::WAFv2::RegexPatternSet",
    "AWS::WAFv2::RuleGroup",
    "AWS::WAFv2::WebACL",
    "AWS::WAFv2::WebACLAssociation",
    // Amazon WorkSpaces
    "AWS::WorkSpaces::ConnectionAlias",
    "AWS::WorkSpaces::Workspace",
    // AWS X-Ray
    "AWS::XRay::Group",
    "AWS::XRay::SamplingRule",
];

/// Whether [`AWS_RESOURCE_TYPES`] publishes `resource_type`.
///
/// Compared byte for byte: a type name is case SENSITIVE, so `aws::s3::bucket` is not
/// `AWS::S3::Bucket`.
pub fn is_published(resource_type: &str) -> bool {
    AWS_RESOURCE_TYPES.contains(&resource_type)
}

/// Whether `resource_type` names a custom resource: `Custom::<Name>` within the documented
/// name alphabet and length, or the generic `AWS::CloudFormation::CustomResource`.
pub fn is_custom_resource(resource_type: &str) -> bool {
    if resource_type == CLOUDFORMATION_CUSTOM_RESOURCE {
        return true;
    }
    let Some(name) = resource_type.strip_prefix(CUSTOM_NAMESPACE_PREFIX) else {
        return false;
    };
    !name.is_empty()
        && name.chars().count() <= MAX_CUSTOM_RESOURCE_NAME_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || CUSTOM_RESOURCE_NAME_PUNCTUATION.contains(&c))
}

/// Whether `resource_type` is one CloudFormation serves itself
/// ([`BUILT_IN_RESOURCE_TYPES`]).
///
/// Compared byte for byte, like every other case: a resource type is case SENSITIVE.
fn is_built_in(resource_type: &str) -> bool {
    BUILT_IN_RESOURCE_TYPES.contains(&resource_type)
}

/// Whether a template may declare a resource of type `resource_type`.
///
/// The four cases of the module documentation: a type CloudFormation serves itself, a
/// published `AWS::` type, a custom resource, or an extension this account's registry holds
/// — and no registry WRITER exists yet, so the last case is empty and a third-party or
/// private type is refused until one does.
pub fn is_recognized(resource_type: &str) -> bool {
    if is_built_in(resource_type) || is_custom_resource(resource_type) {
        return true;
    }
    // `AWS::` is Amazon Web Services' own namespace, and the catalogue is what it holds.
    // Any other namespace is a third-party or a private extension, which this account's
    // registry would have to hold first.
    resource_type.starts_with(AWS_NAMESPACE_PREFIX) && is_published(resource_type)
}

/// The types `declared` names that [`is_recognized`] does not, in the order of the
/// declarations given and without repetition.
///
/// A resource the template declares under a `Condition` counts: the type has to be
/// recognised for CloudFormation to read the template at all, which happens before any
/// condition is evaluated — the same way an IAM resource under a condition still requires
/// its capability (`super::template::required_capabilities`).
pub fn unrecognized<'a>(
    declared: impl IntoIterator<Item = &'a DeclaredResource>,
) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for resource in declared {
        if is_recognized(&resource.resource_type) || found.contains(&resource.resource_type) {
            continue;
        }
        found.push(resource.resource_type.clone());
    }
    found
}

/// The `ValidationError` message naming the types a template declared that CloudFormation
/// does not recognise, as the service words it: `Template format error: Unrecognized
/// resource types: [<type>, <type>]`.
///
/// Both halves are the recorded wording. The `Template format error: ` prefix is what
/// CloudFormation puts on a refusal of the template BODY (the same prefix the
/// no-resources and over-long-description refusals carry in
/// `crate::ops::validate_template`), and the list is the types, in the order they were
/// found and separated by `, `.
pub fn unrecognized_message(types: &[String]) -> String {
    format!(
        "{TEMPLATE_FORMAT_ERROR_PREFIX}Unrecognized resource types: [{}]",
        types.join(", ")
    )
}

/// The types `template` declares that [`is_recognized`] does not, with the TRANSFORM rule
/// already applied: a template declaring a `Transform` names none, because a macro's
/// expansion is what CloudFormation validates (see the module docs) and the only macro this
/// emulator expands has already been expanded by the time a template reaches here.
///
/// The types are listed in the order the BODY declares the resources that have them
/// ([`super::declaration_order`]), which is the order the refusal names them in and the order
/// they are reported as warnings in.
///
/// The ONE place that rule lives: [`refuse_unrecognized`] is this list refused, and an
/// operation that REPORTS the types instead (`GetTemplateSummary`'s
/// `Warnings$UnrecognizedResourceTypes`, where the request asks for warnings rather than an
/// error) reports this same list.
pub fn unrecognized_in(body: &str, template: &Template) -> Vec<String> {
    if !template.transforms.is_empty() {
        return Vec::new();
    }
    let declared = super::declaration_order::as_declared(
        body,
        super::declaration_order::RESOURCES,
        &template.resources,
        |resource| resource.logical_id.as_str(),
    );
    unrecognized(declared)
}

/// `Err(message)` for a template declaring a resource type CloudFormation does not
/// recognise — the refusal a submitted template is held to before anything is created.
///
/// `Ok(())` for a template that declares a `Transform`, which [`unrecognized_in`] is what
/// decides.
pub fn refuse_unrecognized(body: &str, template: &Template) -> Result<(), String> {
    let unrecognized = unrecognized_in(body, template);
    if unrecognized.is_empty() {
        return Ok(());
    }
    Err(unrecognized_message(&unrecognized))
}

/// The types `template` declares that `snapshot` says CloudFormation does not offer in
/// `region`, in declaration order and without repetition.
///
/// A type or a Region the snapshot does not list is never named (see
/// `service_common::region_availability`), and neither is any type of a template that
/// declares a `Transform`, for the reason [`unrecognized_in`] gives. A resource under a
/// `Condition` counts, as it does there.
pub fn unavailable_in(
    body: &str,
    template: &Template,
    region: &str,
    snapshot: &service_common::region_availability::Snapshot,
) -> Vec<String> {
    use service_common::region_availability::Verdict;
    if !template.transforms.is_empty() {
        return Vec::new();
    }
    let declared = super::declaration_order::as_declared(
        body,
        super::declaration_order::RESOURCES,
        &template.resources,
        |resource| resource.logical_id.as_str(),
    );
    let mut found: Vec<String> = Vec::new();
    for resource in declared {
        if snapshot.cfn_resource_type(region, &resource.resource_type) == Verdict::Unavailable
            && !found.contains(&resource.resource_type)
        {
            found.push(resource.resource_type.clone());
        }
    }
    found
}

/// `Err(message)` for a template declaring a type `snapshot` says AWS does not offer in
/// `region`, or `Ok(())`. `Mode::Warn` logs the message and admits the template; `Mode::Off`
/// does not look.
pub fn refuse_unavailable(
    mode: service_common::region_availability::Mode,
    body: &str,
    template: &Template,
    region: &str,
    snapshot: &service_common::region_availability::Snapshot,
) -> Result<(), String> {
    use service_common::region_availability::Mode;
    if mode == Mode::Off {
        return Ok(());
    }
    let types = unavailable_in(body, template, region, snapshot);
    if types.is_empty() {
        return Ok(());
    }
    let message = unavailable_message(&types, region, snapshot);
    if mode == Mode::Warn {
        tracing::warn!("{message}");
        return Ok(());
    }
    Err(message)
}

/// The refusal for types AWS does not offer in `region`: CloudFormation's own sentence for a
/// type it does not know (which is what it answers there), then the Region and the date of
/// the data that says so, so the reader can tell this refusal from a misspelled type.
pub fn unavailable_message(
    types: &[String],
    region: &str,
    snapshot: &service_common::region_availability::Snapshot,
) -> String {
    format!(
        "{} (AWS Regional availability data of {} lists {} as not available in {region}; \
         set {}=off to skip this check)",
        unrecognized_message(types),
        snapshot.data_date(),
        if types.len() == 1 { "it" } else { "them" },
        service_common::region_availability::MODE_ENV,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every catalogue entry is spelled as a resource type: the `AWS::` namespace, a
    /// service namespace and a resource name, with no repetition.
    #[test]
    fn the_catalogue_is_well_formed() {
        for (index, entry) in AWS_RESOURCE_TYPES.iter().enumerate() {
            let segments: Vec<&str> = entry.split("::").collect();
            assert_eq!(
                segments.len(),
                3,
                "entry {entry:?}: expected three `::`-separated segments, got {segments:?}"
            );
            assert_eq!(
                segments[0], "AWS",
                "entry {entry:?}: expected the AWS namespace, got {:?}",
                segments[0]
            );
            assert!(
                segments[1..].iter().all(|segment| !segment.is_empty()),
                "entry {entry:?}: expected non-empty segments, got {segments:?}"
            );
            assert!(
                !AWS_RESOURCE_TYPES[index + 1..].contains(entry),
                "entry {entry:?}: expected one occurrence in the catalogue, found more"
            );
        }
    }

    /// A custom resource's name is held to its documented alphabet and length.
    #[test]
    fn custom_resource_names_follow_the_documented_rule() {
        let longest = format!(
            "{CUSTOM_NAMESPACE_PREFIX}{}",
            "a".repeat(MAX_CUSTOM_RESOURCE_NAME_CHARS)
        );
        let too_long = format!(
            "{CUSTOM_NAMESPACE_PREFIX}{}",
            "a".repeat(MAX_CUSTOM_RESOURCE_NAME_CHARS + 1)
        );
        let cases: &[(&str, bool)] = &[
            ("Custom::Provisioner", true),
            ("Custom::my_resource@v-1", true),
            (longest.as_str(), true),
            (too_long.as_str(), false),
            ("Custom::", false),
            ("Custom::has space", false),
            ("Custom::has/slash", false),
            (CLOUDFORMATION_CUSTOM_RESOURCE, true),
        ];
        for (spelled, expected) in cases {
            assert_eq!(
                is_recognized(spelled),
                *expected,
                "case {spelled:?}: expected recognized={expected}, got {}",
                is_recognized(spelled)
            );
        }
    }

    /// The refusal's wording, as recorded: the template-format prefix, then the types it
    /// did not recognise in brackets, separated by `, `.
    #[test]
    fn the_refusal_names_every_type_it_did_not_recognize() {
        let cases: &[(&[&str], &str)] = &[
            (
                &["AWS::SWF::Domain"],
                "Template format error: Unrecognized resource types: [AWS::SWF::Domain]",
            ),
            (
                &["AWS::SWF::Domain", "MyOrg::Analytics::Pipeline"],
                "Template format error: Unrecognized resource types: \
                 [AWS::SWF::Domain, MyOrg::Analytics::Pipeline]",
            ),
        ];
        for (types, expected) in cases {
            let types: Vec<String> = types.iter().map(|entry| (*entry).to_string()).collect();
            let message = unrecognized_message(&types);
            assert_eq!(
                message, *expected,
                "case {types:?}: expected {expected:?}, got {message:?}"
            );
        }
    }

    /// A type CloudFormation serves itself is recognised without the catalogue carrying it,
    /// and a near miss of one is not.
    #[test]
    fn a_built_in_type_is_recognized_and_a_near_miss_is_not() {
        for resource_type in BUILT_IN_RESOURCE_TYPES {
            assert!(
                is_recognized(resource_type),
                "type {resource_type:?}: expected a type CloudFormation serves itself to be \
                 recognized, it is not"
            );
            assert!(
                !is_published(resource_type),
                "type {resource_type:?}: expected the published catalogue not to carry a type \
                 CloudFormation serves itself, it does"
            );
            for near_miss in [
                format!("{resource_type}Nope"),
                resource_type.to_ascii_lowercase(),
                format!("{resource_type}s"),
            ] {
                assert!(
                    !is_recognized(&near_miss),
                    "type {near_miss:?}: expected a near miss of a built-in type to be \
                     unrecognized, it is recognized"
                );
            }
        }
    }

    /// The types this emulator carries published return values for are types a template
    /// may declare: the implemented set is a SUBSET of the catalogue.
    #[test]
    fn every_implemented_type_is_catalogued() {
        for resource_type in super::super::template::IMPLEMENTED_RESOURCE_TYPES {
            assert!(
                is_recognized(resource_type),
                "type {resource_type:?}: expected the catalogue to carry an implemented \
                 resource type, it does not"
            );
        }
    }

    /// A template names the types the snapshot says the Region lacks, once each and in the
    /// order it declares them, and names nothing for a Region that has them, a type the data
    /// does not list, or a template whose `Transform` may expand into other types.
    #[test]
    fn a_template_names_only_the_types_the_region_lacks() {
        use service_common::region_availability::{Mode, Snapshot};
        let snapshot = Snapshot::parse(
            "# last_updated 2026-11-17T00:03:09+00:00\n# regions us-east-1 ap-southeast-7\n\
             AWS::MemoryDB::Cluster 1\nAWS::MemoryDB::User 1\nAWS::SQS::Queue 3\n",
        )
        .unwrap();
        let resources = r#""Resources": {
            "Db": {"Type": "AWS::MemoryDB::Cluster"},
            "Queue": {"Type": "AWS::SQS::Queue"},
            "Custom": {"Type": "Custom::Thing"},
            "Db2": {"Type": "AWS::MemoryDB::Cluster"},
            "User": {"Type": "AWS::MemoryDB::User"}
        }"#;
        let plain = format!("{{{resources}}}");
        let transformed = format!(r#"{{"Transform": "MyMacro", {resources}}}"#);
        let named = |body: &str, region: &str| {
            let template = super::super::template::parse(body).unwrap();
            unavailable_in(body, &template, region, &snapshot)
        };
        assert_eq!(
            named(&plain, "ap-southeast-7"),
            ["AWS::MemoryDB::Cluster", "AWS::MemoryDB::User"]
        );
        assert!(named(&plain, "us-east-1").is_empty());
        let template = super::super::template::parse(&plain).unwrap();
        let refuse =
            |mode| refuse_unavailable(mode, &plain, &template, "ap-southeast-7", &snapshot);
        assert!(refuse(Mode::Enforce).is_err());
        assert!(refuse(Mode::Warn).is_ok(), "warn admits the template");
        assert!(refuse(Mode::Off).is_ok(), "off does not look");
        assert!(named(&plain, "xx-test-1").is_empty());
        assert!(named(&transformed, "ap-southeast-7").is_empty());
        let message = unavailable_message(
            &named(&plain, "ap-southeast-7"),
            "ap-southeast-7",
            &snapshot,
        );
        assert_eq!(
            message,
            "Template format error: Unrecognized resource types: \
             [AWS::MemoryDB::Cluster, AWS::MemoryDB::User] (AWS Regional availability data of \
             2026-11-17 lists them as not available in ap-southeast-7; set \
             EMULATOR_REGION_AVAILABILITY=off to skip this check)"
        );
    }

    /// The bundled data, decoded a second time here by a reader that shares no code with the
    /// loader, so the sweeps below hold the gate to the data and not to itself.
    fn independent_decode() -> (
        Vec<&'static str>,
        std::collections::HashMap<&'static str, u64>,
    ) {
        const TEXT: &str = include_str!("../../../common/data/cfn_resource_availability.txt");
        let regions = TEXT
            .lines()
            .find_map(|line| line.strip_prefix("# regions "))
            .expect("a regions header")
            .split_whitespace()
            .collect();
        let masks = TEXT
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let (name, mask) = line.rsplit_once(' ').expect("a type and a mask");
                (name, u64::from_str_radix(mask, 16).expect("a hex mask"))
            })
            .collect();
        (regions, masks)
    }

    fn one_resource(resource_type: &str) -> String {
        format!(r#"{{"Resources":{{"R":{{"Type":"{resource_type}"}}}}}}"#)
    }

    /// Every catalogued type in every Region the data lists: a pair the data marks
    /// unavailable is refused, naming the type and the Region, and every other pair is
    /// admitted. So there are no missed refusals and no false ones, over the whole table.
    /// Also, per Region, one template holding every missing type is refused naming exactly
    /// those types, in declaration order.
    #[test]
    fn every_pair_the_data_marks_unavailable_is_refused_and_every_other_is_admitted() {
        use service_common::region_availability::{Mode, Snapshot};
        let snapshot = Snapshot::bundled();
        let (regions, masks) = independent_decode();
        let (mut refused, mut admitted, mut not_in_data) = (0usize, 0usize, 0usize);
        for (bit, region) in regions.iter().enumerate() {
            let mut missing_here: Vec<String> = Vec::new();
            for resource_type in AWS_RESOURCE_TYPES {
                let body = one_resource(resource_type);
                let template = super::super::template::parse(&body).unwrap();
                let outcome = refuse_unavailable(Mode::Enforce, &body, &template, region, snapshot);
                match masks.get(resource_type) {
                    Some(mask) if mask >> bit & 1 == 0 => {
                        let message = outcome.expect_err("a missing type must be refused");
                        assert!(
                            message.contains(&format!("[{resource_type}]"))
                                && message.contains(&format!("not available in {region};")),
                            "{resource_type} in {region}: {message}"
                        );
                        missing_here.push((*resource_type).to_string());
                        refused += 1;
                    }
                    Some(_) => {
                        assert_eq!(outcome, Ok(()), "{resource_type} in {region}");
                        admitted += 1;
                    }
                    None => {
                        assert_eq!(outcome, Ok(()), "{resource_type} in {region}");
                        not_in_data += 1;
                    }
                }
            }
            println!(
                "  {region}: refuses {} of {} catalogue types",
                missing_here.len(),
                AWS_RESOURCE_TYPES.len()
            );
            let resources: Vec<String> = missing_here
                .iter()
                .enumerate()
                .map(|(index, resource_type)| format!(r#""R{index}":{{"Type":"{resource_type}"}}"#))
                .collect();
            let body = format!(r#"{{"Resources":{{{}}}}}"#, resources.join(","));
            let template = super::super::template::parse(&body).unwrap();
            assert_eq!(
                unavailable_in(&body, &template, region, snapshot),
                missing_here,
                "one template holding every missing type in {region}"
            );
        }
        println!(
            "sweep: {} Regions x {} catalogue types = {} pairs; refused {refused}, admitted \
             {admitted}, type not in data {not_in_data}",
            regions.len(),
            AWS_RESOURCE_TYPES.len(),
            refused + admitted + not_in_data
        );
        assert_eq!(
            refused + admitted + not_in_data,
            regions.len() * AWS_RESOURCE_TYPES.len()
        );
        assert!(refused > 0 && admitted > 0 && not_in_data > 0);
    }

    /// What the data does not list is never refused: a Region it omits (a Region newer than
    /// the data, or a partition it leaves out) for every catalogued type, and a type it omits
    /// in every Region it lists.
    #[test]
    fn a_region_or_type_the_data_does_not_list_is_never_refused() {
        use service_common::region_availability::{Mode, Snapshot};
        let snapshot = Snapshot::bundled();
        let (regions, _) = independent_decode();
        let admitted = |region: &str, resource_type: &str| {
            let body = one_resource(resource_type);
            let template = super::super::template::parse(&body).unwrap();
            refuse_unavailable(Mode::Enforce, &body, &template, region, snapshot) == Ok(())
        };
        let mut checked = 0usize;
        for region in ["xx-test-1", "cn-north-1", "cn-northwest-1", ""] {
            for resource_type in AWS_RESOURCE_TYPES {
                assert!(
                    admitted(region, resource_type),
                    "{resource_type} in {region:?}"
                );
                checked += 1;
            }
        }
        for region in &regions {
            for resource_type in ["AWS::Made::Up", "Custom::Thing", "AWS::CDK::Metadata"] {
                assert!(
                    admitted(region, resource_type),
                    "{resource_type} in {region}"
                );
                checked += 1;
            }
        }
        println!("unlisted sweep: {checked} pairs admitted");
    }
}
