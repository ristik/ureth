//! The V3 protocol tuple (`q3format/config.go`).

use crate::{
    cbor::{Items, Writer},
    error::{Error, Kind, Result},
    sig::sha256,
};

const CONFIG_DOMAIN: &str = "UNICITY_Q3_PROTOCOL_CONFIG";
const CONFIG_FIELDS: usize = 11;
const MAX_CONFIG_TEXT: usize = 32;
/// The only revision of the tuple.
pub const CONFIG_REVISION: u64 = 1;

/// The one immutable protocol tuple a successor root epoch activates. `network` and `genesis` are
/// the chain's, not an epoch's. There is no independently configurable member: any value other than
/// the Q3 one, and so any partial combination, is invalid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolConfig {
    /// Tuple revision.
    pub revision: u64,
    /// Network identifier.
    pub network: u64,
    /// The trusted root-genesis identity, never the changing epoch-anchor id.
    pub genesis: [u8; 32],
    /// Q1 signing scheme.
    pub signing_scheme: u64,
    /// Vote codec.
    pub vote_codec: u64,
    /// Quorum profile.
    pub quorum_profile: String,
    /// EVM request policy.
    pub evm_request_policy: String,
    /// Aggregator policy.
    pub aggregator_policy: String,
    /// Required root peer protocol.
    pub required_peer_protocol: String,
    /// Required execution protocol.
    pub required_execution_protocol: String,
    /// Registry layout.
    pub registry_layout: u64,
}

impl ProtocolConfig {
    /// The single valid tuple for a chain.
    pub fn q3(network: u64, genesis: [u8; 32]) -> Self {
        Self {
            revision: CONFIG_REVISION,
            network,
            genesis,
            signing_scheme: 2,
            vote_codec: 2,
            quorum_profile: "D3".into(),
            evm_request_policy: "mirrored-root-v1".into(),
            aggregator_policy: "unit-v1".into(),
            required_peer_protocol: "q3/1".into(),
            required_execution_protocol: "q3/1".into(),
            registry_layout: 2,
        }
    }

    /// Refuses a tuple that differs from [`ProtocolConfig::q3`] in any field, naming the first that
    /// differs.
    pub fn validate(&self) -> Result<()> {
        if self.network == 0 || self.genesis == [0; 32] {
            return Err(Error::new(Kind::Config, "network and genesis are required"));
        }
        let w = Self::q3(self.network, self.genesis);
        let fields: [(&str, String, String); 9] = [
            ("revision", self.revision.to_string(), w.revision.to_string()),
            ("signingScheme", self.signing_scheme.to_string(), w.signing_scheme.to_string()),
            ("voteCodec", self.vote_codec.to_string(), w.vote_codec.to_string()),
            ("quorumProfile", self.quorum_profile.clone(), w.quorum_profile),
            ("evmRequestPolicy", self.evm_request_policy.clone(), w.evm_request_policy),
            ("aggregatorPolicy", self.aggregator_policy.clone(), w.aggregator_policy),
            ("requiredPeerProtocol", self.required_peer_protocol.clone(), w.required_peer_protocol),
            (
                "requiredExecutionProtocol",
                self.required_execution_protocol.clone(),
                w.required_execution_protocol,
            ),
            ("registryLayout", self.registry_layout.to_string(), w.registry_layout.to_string()),
        ];
        for (name, got, want) in fields {
            if got != want {
                return Err(Error::new(Kind::Config, format_args!("{name} is {got}, want {want}")));
            }
        }
        Ok(())
    }

    pub(crate) fn write_fields(&self, w: &mut Writer) {
        w.array(CONFIG_FIELDS)
            .uint(self.revision)
            .uint(self.network)
            .bytes(&self.genesis)
            .uint(self.signing_scheme)
            .uint(self.vote_codec)
            .text(&self.quorum_profile)
            .text(&self.evm_request_policy)
            .text(&self.aggregator_policy)
            .text(&self.required_peer_protocol)
            .text(&self.required_execution_protocol)
            .uint(self.registry_layout);
    }

    /// The canonical `["UNICITY_Q3_PROTOCOL_CONFIG", fields]` encoding the identity hashes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(2).text(CONFIG_DOMAIN);
        self.write_fields(&mut w);
        w.finish()
    }

    /// The hash of the tuple alone; the activation and the readiness receipts name it.
    pub fn identity(&self) -> [u8; 32] {
        sha256(&self.encode())
    }

    pub(crate) fn read(r: &mut Items<'_>) -> Result<Self> {
        let mut f = r.sub(CONFIG_FIELDS)?;
        let c = Self {
            revision: f.uint()?,
            network: f.uint()?,
            genesis: f
                .bytes_exact(32)?
                .try_into()
                .map_err(|_| Error::new(Kind::Format, "genesis"))?,
            signing_scheme: f.uint()?,
            vote_codec: f.uint()?,
            quorum_profile: f.text(MAX_CONFIG_TEXT)?.to_owned(),
            evm_request_policy: f.text(MAX_CONFIG_TEXT)?.to_owned(),
            aggregator_policy: f.text(MAX_CONFIG_TEXT)?.to_owned(),
            required_peer_protocol: f.text(MAX_CONFIG_TEXT)?.to_owned(),
            required_execution_protocol: f.text(MAX_CONFIG_TEXT)?.to_owned(),
            registry_layout: f.uint()?,
        };
        f.done()?;
        Ok(c)
    }
}
