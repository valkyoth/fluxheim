use std::error::Error;

use crate::config::Config;

pub(crate) fn print_runtime_cutover_report(
    config: &Config,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    print!("{}", runtime_cutover_report(config)?);
    Ok(())
}

pub(crate) fn runtime_cutover_report(
    config: &Config,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let plan = fluxheim_server::ServerPlan::from_config(config)?;
    let summary = plan.native_runtime_cutover_summary();
    let mut report = format!(
        "native-runtime-plan-adapter: {:?}\n",
        plan.runtime_adapter()
    );
    report.push_str(&format!(
        "native-runtime-target-adapter: {:?}\n",
        plan.native_runtime_target_adapter()
    ));
    report.push_str(&summary.to_tsv());
    report.push_str("native-http1-proxy-candidate\tscope\tstatus\treason\n");
    for candidate in plan.native_http1_proxy_candidates() {
        report.push_str("native-http1-proxy-candidate\t");
        report.push_str(&runtime_cutover_field(candidate.scope()));
        report.push('\t');
        if let Some(reason) = candidate.unsupported_reason() {
            report.push_str("compatibility-required\t");
            report.push_str(&runtime_cutover_field(&reason.to_string()));
        } else {
            report.push_str("native-ready\t");
            report.push('-');
        }
        report.push('\n');
    }
    if let Ok(manifest) = plan.native_runtime_manifest() {
        report.push_str(&manifest.to_tsv());
    }
    match plan.native_runtime_launch_plan() {
        Ok(launch_plan) => report.push_str(&launch_plan.to_tsv()),
        Err(error) => {
            report.push_str("native-runtime-launch-plan-error\tkind\tdetail\n");
            report.push_str("native-runtime-launch-plan-error\t");
            report.push_str(native_runtime_launch_plan_error_kind(&error));
            report.push('\t');
            report.push_str(&runtime_cutover_field(&error.to_string()));
            report.push('\n');
        }
    }
    Ok(report)
}

fn native_runtime_launch_plan_error_kind(
    error: &fluxheim_server::NativeRuntimeLaunchPlanError,
) -> &'static str {
    match error {
        fluxheim_server::NativeRuntimeLaunchPlanError::Blocked { .. } => "blocked",
        fluxheim_server::NativeRuntimeLaunchPlanError::DuplicateService { .. } => {
            "duplicate-service"
        }
        fluxheim_server::NativeRuntimeLaunchPlanError::DuplicateListener { .. } => {
            "duplicate-listener"
        }
        fluxheim_server::NativeRuntimeLaunchPlanError::DuplicateBackgroundTask { .. } => {
            "duplicate-background-task"
        }
    }
}

fn runtime_cutover_field(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\t' | '\n' | '\r' => ' ',
            character => character,
        })
        .collect()
}
