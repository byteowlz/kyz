//! MCP server for rust-workspace.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{Args, Parser};
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
    tool, tool_handler, tool_router,
    transport::io::stdio,
};

use rmcp::schemars;

use kyz_core::{AppConfig, AppPaths};

fn main() -> anyhow::Result<()> {
    try_main()
}

#[tokio::main]
async fn try_main() -> Result<()> {
    let cli = Cli::parse();
    let paths = AppPaths::discover(cli.common.config.as_deref())?;
    let config = AppConfig::load(&paths, false)?;

    let server = McpServer::new(config);
    let transport = stdio();

    let service = server
        .serve(transport)
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;

    service.waiting().await?;

    Ok(())
}

#[derive(Debug, Parser)]
#[command(author, version, about = "MCP server for rust-workspace")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
}

#[derive(Debug, Clone, Args)]
struct CommonOpts {
    /// Override the config file path
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

/// Parameters for the echo tool
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct EchoParams {
    /// The message to echo back
    message: String,
}

#[derive(Clone)]
struct McpServer {
    config: Arc<AppConfig>,
    tool_router: ToolRouter<Self>,
}

impl McpServer {
    fn new(config: AppConfig) -> Self {
        Self {
            config: Arc::new(config),
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl McpServer {
    /// Get the current configuration profile
    #[tool(description = "Returns the current configuration profile name")]
    async fn get_profile(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(
            self.config.profile.clone(),
        )]))
    }

    /// Echo a message back
    #[tool(description = "Echoes the provided message back")]
    async fn echo(
        &self,
        Parameters(params): Parameters<EchoParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Echo: {}",
            params.message
        ))]))
    }

    /// Get runtime configuration
    #[tool(description = "Returns the runtime configuration including parallelism and timeout")]
    async fn get_runtime_config(&self) -> Result<CallToolResult, McpError> {
        let json = serde_json::to_string_pretty(&self.config.runtime)
            .unwrap_or_else(|_| "{}".to_string());
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

#[tool_handler]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("MCP server for rust-workspace template".to_string()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}
