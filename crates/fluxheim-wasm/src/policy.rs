#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WasmAccessDecision {
    Continue,
    Allow,
    Deny(WasmAccessDeny),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WasmAccessDeny {
    pub status: u16,
    pub reason: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WasmAccessChainDecision {
    Allow,
    Deny(WasmAccessDeny),
}

pub fn combine_access_decisions<I>(decisions: I) -> WasmAccessChainDecision
where
    I: IntoIterator<Item = WasmAccessDecision>,
{
    for decision in decisions {
        if let WasmAccessDecision::Deny(deny) = decision {
            return WasmAccessChainDecision::Deny(deny);
        }
    }
    WasmAccessChainDecision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_chain_allows_when_no_plugin_denies() {
        let decision = combine_access_decisions([
            WasmAccessDecision::Continue,
            WasmAccessDecision::Allow,
            WasmAccessDecision::Continue,
        ]);

        assert_eq!(decision, WasmAccessChainDecision::Allow);
    }

    #[test]
    fn access_chain_uses_first_deny() {
        let first = WasmAccessDeny {
            status: 403,
            reason: "first".to_owned(),
        };
        let second = WasmAccessDeny {
            status: 451,
            reason: "second".to_owned(),
        };

        let decision = combine_access_decisions([
            WasmAccessDecision::Allow,
            WasmAccessDecision::Deny(first.clone()),
            WasmAccessDecision::Deny(second),
        ]);

        assert_eq!(decision, WasmAccessChainDecision::Deny(first));
    }
}
