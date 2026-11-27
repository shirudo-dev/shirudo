// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::util::config_measure::CONFIG_NVPCR_INDEX;

fn one_event(pcr: u32) -> Evidence {
    let mut initial = [0x11; 32];
    if nvpcr(pcr) {
        assert_eq!(nvpcr_initial(&mut initial), 0);
    }
    let root = [0x42; 32];
    let event = measure_event(EVENT_BOOT, &root).unwrap();
    let mut value = initial;
    assert_eq!(chain::fold(&mut value, &event), Ok(()));
    Evidence {
        events: vec![EvidenceEvent {
            root_hash: root,
            sequence: 1,
            kind: EVENT_BOOT,
        }],
        initial_pcr: initial,
        value,
        reset_count: 7,
        restart_count: 3,
        pcr,
        present: true,
    }
}

#[test]
#[cfg_attr(miri, ignore = "OpenSSL SHA-256 is foreign code")]
fn pcr_replay_follows_reset_count_across_a_restart() {
    let view = one_event(15);
    let mut pcrs = [[0u8; 32]; 24];
    pcrs[15] = view.value;
    let mut quote = Quote {
        mask: 1 << 15,
        reset: 7,
        pcrs: &pcrs,
        nvpcr: None,
    };
    assert_eq!(verify(&view, &quote, Some(&[0x42; 32]), Some(15)).0, 0);
    quote.reset = 8;
    assert_eq!(
        verify(&view, &quote, Some(&[0x42; 32]), Some(15)).0,
        -EKEYREJECTED
    );
}

#[test]
#[cfg_attr(miri, ignore = "OpenSSL SHA-256 is foreign code")]
fn nvpcr_replay_follows_reset_count_and_its_fixed_start() {
    let view = one_event(CONFIG_NVPCR_INDEX);
    let pcrs = [[0u8; 32]; 24];
    let certified = view.value;
    let mut quote = Quote {
        mask: 0,
        reset: 7,
        pcrs: &pcrs,
        nvpcr: Some(&certified),
    };
    assert_eq!(
        verify(&view, &quote, Some(&[0x42; 32]), Some(CONFIG_NVPCR_INDEX)).0,
        0
    );
    quote.reset = 8;
    assert_eq!(
        verify(&view, &quote, Some(&[0x42; 32]), Some(CONFIG_NVPCR_INDEX)).0,
        -EKEYREJECTED
    );
    quote.reset = 7;
    let mut wrong_start = one_event(CONFIG_NVPCR_INDEX);
    wrong_start.initial_pcr = [0; 32];
    assert_eq!(
        verify(
            &wrong_start,
            &quote,
            Some(&[0x42; 32]),
            Some(CONFIG_NVPCR_INDEX)
        )
        .0,
        -EKEYREJECTED
    );
}
