use thiserror::Error;

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum Curve25519Error {
    #[error("pod conversion failed")]
    PodConversion,
}
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum BLS12381Error {
    #[error("pod conversion failed")]
    PodConversion,
}
