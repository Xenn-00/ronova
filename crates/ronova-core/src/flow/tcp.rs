use serde::Serialize;

use crate::{flow::Direction, packet::ParsedTcp};

// Represents the TCP control flags observed in one TCP segment.
//
// Die Untersuchung der TCP-Flags bleibt bewusst auf Paketebene,
// damit die spätere TCP-State-Machine die Sequenz mehrerer
// Beobachtungen selbst interpretieren kann.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TcpObservation {
    // Indicates that the SYN flag was observed.
    pub syn: bool,

    // Indicates that the ACK flag was observed.
    pub ack: bool,

    // Indicates that the FIN flag was observed.
    pub fin: bool,

    // Indicates that the RST flag was observed.
    pub rst: bool,
}

impl TcpObservation {
    // Creates a TCP observation from a parsed TCP segment.
    //
    // Die Flow-Schicht übernimmt nur die für die TCP-Lebenszyklus-Analyse
    // relevanten Contril-Flags und bleibt unabhängig von den überigen Parser-Details.
    pub fn from_tcp(tcp: &ParsedTcp) -> Self {
        Self {
            syn: tcp.syn,
            ack: tcp.ack,
            fin: tcp.fin,
            rst: tcp.rst,
        }
    }
}

// Represents the lifecycle state of an observed TCP flow.
//
// Die Zustände beschreiben nur das, was Ronova anhand der
// beobachteten TCP-Segmente sicher ableiten kann, nicht den
// vollständigen internen TCP-Zustand der Endpunkte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpLifecycleState {
    // No sufficient TCP lifecycle evidence has been observed yet.
    //
    // Dieser Zustand bleibt bewusst konservativ, wenn der Mitschnitt
    // beispielweise mitten in einer bereits bestehenden Verbindung beginnt.
    #[default]
    New,

    // A SYN has been observed without a corresponding SYN-ACK yet.
    //
    // Ronova kennt damit einen beobachteten Verbindungsversuch,
    // aber noch keinen vollständigen Handshake.
    SynSent,
    // A SYN-ACK has been observed, but the final ACK has not been observed yet.
    //
    // Der Handshake ist noch nicht vollständig durch die beobachteten
    // Pakete bestätigt.
    SynReceived,

    // The TCP handshake has been sufficiently observed to consider the flow established.
    //
    // Dieser Zustand bedeutet "Handshake beobachtet" und nicht,
    // dass Ronova den internen Zustand beider TCP-Stacks kennt.
    Established,

    // A FIN has been observed from an established connection.
    //
    // Die Beendigung wurde eingeleitet, aber ein FIN aus der Gegenrichtung
    // wurde noch nicht beobachtet.
    Closing,

    // FIN has been observed from both directions.
    //
    // Ronova hat damit ausreichende Evidenz für ein normales Ende
    // des beobachteten TCP-Lebenszyklus.
    Closed,

    // A TCP reset has been observed.
    //
    // Ein RST beendet den beobachteten Lebenszyklus unmittelbar.
    Reset,
}

// Tracks the lifecycle of one observed TCP flow.
//
// Die Lifecycle-Information bleibt von den einzelnen TCP-Paketflags getrennt,
// damit TcpObservation weiterhin nur ein einzelnes Segment beschreibt.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TcpLifecycle {
    state: TcpLifecycleState,
    fin_a_to_b: bool,
    fin_b_to_a: bool,
}

impl TcpLifecycle {
    // Returns the current lifecycle state.
    //
    // Der Getter erlaubt anderen Flow-Komponenten, den aktuellen
    // semantischen Zustand zu verwenden, ohne interne Felder freizugeben.
    pub fn state(&self) -> TcpLifecycleState {
        self.state
    }

    // Applies one observed TCP segment to the lifecycle state.
    //
    // Die Transition basiert ausschließlich auf beobachteten Paketen.
    // Fehlende Pakete werden daher nicht durch Annahmen ersetzt.
    pub fn observe(&mut self, direction: Direction, observation: TcpObservation) {
        if observation.rst {
            self.state = TcpLifecycleState::Reset;
            return;
        }

        match self.state {
            TcpLifecycleState::New => {
                if observation.syn && !observation.ack {
                    self.state = TcpLifecycleState::SynSent;
                } else if observation.syn && observation.ack {
                    self.state = TcpLifecycleState::SynReceived;
                }
            }

            TcpLifecycleState::SynSent => {
                if observation.syn && observation.ack {
                    self.state = TcpLifecycleState::SynReceived;
                }
            }

            TcpLifecycleState::SynReceived => {
                if observation.ack && !observation.syn {
                    self.state = TcpLifecycleState::Established;
                }
            }

            TcpLifecycleState::Established => {
                if observation.fin {
                    self.record_fin(direction);
                    self.state = TcpLifecycleState::Closing;
                }
            }

            TcpLifecycleState::Closing => {
                if observation.fin {
                    self.record_fin(direction);

                    if self.fin_a_to_b && self.fin_b_to_a {
                        self.state = TcpLifecycleState::Closed;
                    }
                }
            }

            TcpLifecycleState::Closed | TcpLifecycleState::Reset => {}
        }
    }

    // Records that a FIN was observed in one flow direction.
    //
    // Die FIN-Richtung wird separat gespeichert, damit ein geschlossenes
    // TCP-Lebensende erst bei FIN aus beiden Richtungen erkannt wird.
    fn record_fin(&mut self, direction: Direction) {
        match direction {
            Direction::AtoB => self.fin_a_to_b = true,
            Direction::BtoA => self.fin_b_to_a = true,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn tcp() -> ParsedTcp {
        ParsedTcp {
            source_port: 49152,
            destination_port: 443,
            sequence_number: 1,
            acknowledgement_number: 0,
            ns: false,
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: false,
            urg: false,
            ece: false,
            cwr: false,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
        }
    }

    fn observation(syn: bool, ack: bool, fin: bool, rst: bool) -> TcpObservation {
        TcpObservation { syn, ack, fin, rst }
    }

    #[test]
    fn extracts_tcp_control_flags() {
        let mut tcp = tcp();

        tcp.syn = true;
        tcp.ack = true;

        let observation = TcpObservation::from_tcp(&tcp);

        assert_eq!(
            observation,
            TcpObservation {
                syn: true,
                ack: true,
                fin: false,
                rst: false
            }
        )
    }

    #[test]
    fn preserves_fin_and_rst_flags() {
        let mut tcp = tcp();

        tcp.fin = true;
        tcp.rst = true;

        let observation = TcpObservation::from_tcp(&tcp);

        assert_eq!(
            observation,
            TcpObservation {
                syn: false,
                ack: false,
                fin: true,
                rst: true
            }
        )
    }

    #[test]
    fn ignores_non_control_flags() {
        let mut tcp = tcp();

        tcp.psh = true;
        tcp.urg = true;
        tcp.ece = true;
        tcp.cwr = true;
        tcp.ns = true;

        let observation = TcpObservation::from_tcp(&tcp);

        assert_eq!(
            observation,
            TcpObservation {
                syn: false,
                ack: false,
                fin: false,
                rst: false,
            }
        );
    }

    #[test]
    fn starts_in_new_state() {
        let lifecycle = TcpLifecycle::default();

        assert_eq!(lifecycle.state(), TcpLifecycleState::New);
    }

    #[test]
    fn transitions_from_new_to_syn_sent() {
        let mut lifecycle = TcpLifecycle::default();

        lifecycle.observe(Direction::AtoB, observation(true, false, false, false));

        assert_eq!(lifecycle.state(), TcpLifecycleState::SynSent)
    }

    #[test]
    fn transition_from_new_to_syn_received_on_syn_ack() {
        let mut lifecycle = TcpLifecycle::default();

        lifecycle.observe(Direction::BtoA, observation(true, true, false, false));

        assert_eq!(lifecycle.state(), TcpLifecycleState::SynReceived)
    }

    #[test]
    fn completes_handshake_to_established() {
        let mut lifecycle = TcpLifecycle::default();

        lifecycle.observe(Direction::AtoB, observation(true, false, false, false));
        lifecycle.observe(Direction::BtoA, observation(true, true, false, false));
        lifecycle.observe(Direction::AtoB, observation(false, true, false, false));

        assert_eq!(lifecycle.state(), TcpLifecycleState::Established);
    }

    #[test]
    fn keeps_syn_sent_on_syn_retransmission() {
        let mut lifecycle = TcpLifecycle::default();

        let syn = observation(true, false, false, false);

        lifecycle.observe(Direction::AtoB, syn);
        lifecycle.observe(Direction::AtoB, syn);

        assert_eq!(lifecycle.state(), TcpLifecycleState::SynSent);
    }

    #[test]
    fn keeps_syn_received_on_syn_ack_retransmission() {
        let mut lifecycle = TcpLifecycle::default();

        let syn = observation(true, false, false, false);
        let syn_ack = observation(true, true, false, false);

        lifecycle.observe(Direction::AtoB, syn);
        lifecycle.observe(Direction::BtoA, syn_ack);
        lifecycle.observe(Direction::BtoA, syn_ack);

        assert_eq!(lifecycle.state(), TcpLifecycleState::SynReceived);
    }

    #[test]
    fn does_not_establish_from_ack_without_handshake_evidence() {
        let mut lifecycle = TcpLifecycle::default();

        lifecycle.observe(Direction::AtoB, observation(false, true, false, false));

        assert_eq!(lifecycle.state(), TcpLifecycleState::New);
    }

    #[test]
    fn transitions_to_closing_on_first_fin() {
        let mut lifecycle = established_lifecycle();

        lifecycle.observe(Direction::AtoB, observation(false, true, true, false));

        assert_eq!(lifecycle.state(), TcpLifecycleState::Closing);
    }

    #[test]
    fn transitions_to_closed_after_fin_from_both_directions() {
        let mut lifecycle = established_lifecycle();

        lifecycle.observe(Direction::AtoB, observation(false, true, true, false));
        lifecycle.observe(Direction::BtoA, observation(false, true, true, false));

        assert_eq!(lifecycle.state(), TcpLifecycleState::Closed);
    }

    #[test]
    fn rst_transitions_to_reset() {
        let mut lifecycle = established_lifecycle();

        lifecycle.observe(Direction::BtoA, observation(false, true, false, true));

        assert_eq!(lifecycle.state(), TcpLifecycleState::Reset);
    }

    #[test]
    fn rst_is_terminal() {
        let mut lifecycle = established_lifecycle();

        lifecycle.observe(Direction::AtoB, observation(false, false, false, true));
        lifecycle.observe(Direction::AtoB, observation(true, false, false, false));

        assert_eq!(lifecycle.state(), TcpLifecycleState::Reset);
    }

    #[test]
    fn fin_does_not_start_closing_before_established() {
        let mut lifecycle = TcpLifecycle::default();

        lifecycle.observe(Direction::AtoB, observation(true, false, true, false));

        assert_eq!(lifecycle.state(), TcpLifecycleState::SynSent);
    }

    #[test]
    fn established_state_ignores_regular_ack() {
        let mut lifecycle = established_lifecycle();

        lifecycle.observe(Direction::BtoA, observation(false, true, false, false));

        assert_eq!(lifecycle.state(), TcpLifecycleState::Established);
    }

    fn established_lifecycle() -> TcpLifecycle {
        let mut lifecycle = TcpLifecycle::default();

        lifecycle.observe(Direction::AtoB, observation(true, false, false, false));
        lifecycle.observe(Direction::BtoA, observation(true, true, false, false));
        lifecycle.observe(Direction::AtoB, observation(false, true, false, false));

        lifecycle
    }
}
