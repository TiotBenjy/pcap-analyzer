use super::*;
use crate::migrate::migrate;
use crate::schema::SESSION_SCHEMA;

fn db() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn, &SESSION_SCHEMA).unwrap();
    conn
}

fn mac_row(last: u8, vendor: Option<&str>, frames: u64, ts: (i64, i64)) -> EthMacRow {
    EthMacRow {
        mac: [0x08, 0x00, 0x27, 0, 0, last],
        vendor: vendor.map(str::to_owned),
        registry: vendor.map(|_| "ma-l".to_owned()),
        kind: "unicast".to_owned(),
        local: false,
        group: None,
        frames_sent: frames,
        bytes_sent: frames * 100,
        frames_received: 0,
        bytes_received: 0,
        first_ts: ts.0,
        last_ts: ts.1,
        vlans: Vec::new(),
    }
}

fn insert(conn: &Connection, row: EthernetRow) {
    row.insert(conn).unwrap();
}

fn macs(conn: &Connection, filter: &MacFilter, sort: MacSort) -> Vec<String> {
    let mut out = Vec::new();
    let mut request = PageRequest::first(2);
    loop {
        let page = macs_page(conn, filter, sort, &request).unwrap();
        out.extend(page.items.into_iter().map(|e| e.addr.mac));
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => break,
        }
    }
    out
}

#[test]
fn address_deltas_merge() {
    let conn = db();
    let mut a = mac_row(1, Some("PCS Systemtechnik GmbH"), 2, (10, 20));
    a.vlans = vec!["10".to_owned()];
    insert(&conn, EthernetRow::Mac(a));
    let mut b = mac_row(1, Some("PCS Systemtechnik GmbH"), 3, (5, 15));
    b.frames_received = 4;
    b.bytes_received = 400;
    b.vlans = vec!["100.20".to_owned(), "10".to_owned()];
    insert(&conn, EthernetRow::Mac(b));

    let page = macs_page(&conn, &MacFilter::default(), MacSort::Frames, &PageRequest::first(10)).unwrap();
    let [e] = page.items.as_slice() else { panic!("one address") };
    assert_eq!(e.addr.mac, "08:00:27:00:00:01");
    assert_eq!((e.frames_sent, e.bytes_sent), (5, 500));
    assert_eq!((e.frames_received, e.bytes_received), (4, 400));
    assert_eq!((e.first_ts, e.last_ts), (5, 20));
    assert_eq!(e.vlans, vec!["10".to_owned(), "100.20".to_owned()]);
    assert_eq!(e.registry.as_deref(), Some("ma-l"));
}

#[test]
fn json_sets_stay_bounded() {
    let conn = db();
    for i in 0..40u32 {
        let mut r = mac_row(1, None, 1, (1, 1));
        r.vlans = vec![format!("{i:03}")];
        insert(&conn, EthernetRow::Mac(r));
    }
    let page = macs_page(&conn, &MacFilter::default(), MacSort::Frames, &PageRequest::first(10)).unwrap();
    assert_eq!(page.items[0].vlans.len(), MAX_SET);
    assert_eq!(page.items[0].frames_sent, 40);
}

fn sample(conn: &Connection) {
    insert(conn, EthernetRow::Mac(mac_row(1, Some("PCS Systemtechnik GmbH"), 10, (100, 200))));
    insert(conn, EthernetRow::Mac(mac_row(2, Some("PCS Systemtechnik GmbH"), 30, (300, 400))));
    insert(conn, EthernetRow::Mac(mac_row(3, Some("Cisco Systems, Inc"), 20, (150, 350))));
    let mut local = mac_row(4, None, 5, (50, 60));
    local.mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x01];
    local.local = true;
    local.vlans = vec!["10".to_owned()];
    insert(conn, EthernetRow::Mac(local));
    let mut unknown = mac_row(5, None, 1, (500, 600));
    unknown.mac = [0x00, 0xff, 0xff, 0x00, 0x00, 0x05];
    insert(conn, EthernetRow::Mac(unknown));
    let mut bcast = mac_row(6, None, 0, (100, 600));
    bcast.mac = [0xff; 6];
    bcast.kind = "broadcast".to_owned();
    bcast.local = true;
    bcast.frames_received = 7;
    insert(conn, EthernetRow::Mac(bcast));
}

#[test]
fn address_sorts_and_keyset_pages() {
    let conn = db();
    sample(&conn);
    let all = MacFilter::default();
    assert_eq!(
        macs(&conn, &all, MacSort::Frames),
        vec![
            "08:00:27:00:00:02",
            "08:00:27:00:00:03",
            "08:00:27:00:00:01",
            "ff:ff:ff:ff:ff:ff",
            "52:55:0a:00:02:01",
            "00:ff:ff:00:00:05",
        ]
    );
    assert_eq!(macs(&conn, &all, MacSort::Mac).first().map(String::as_str), Some("00:ff:ff:00:00:05"));
    assert_eq!(macs(&conn, &all, MacSort::FirstSeen).first().map(String::as_str), Some("52:55:0a:00:02:01"));
    assert_eq!(macs(&conn, &all, MacSort::LastSeen).last().map(String::as_str), Some("52:55:0a:00:02:01"));
    assert_eq!(count_macs(&conn, &all).unwrap(), 6);
}

#[test]
fn address_filters() {
    let conn = db();
    sample(&conn);
    let f = |filter: MacFilter| macs(&conn, &filter, MacSort::Mac);
    // Address in any notation, or vendor name (case-insensitive).
    for q in ["08:00:27", "08-00-27", "080027", "pcs system"] {
        assert_eq!(
            f(MacFilter { q: Some(q.to_owned()), ..MacFilter::default() }).len(),
            if q.starts_with("pcs") { 2 } else { 3 },
            "{q}"
        );
    }
    // LIKE wildcards are literal.
    assert!(f(MacFilter { q: Some("%".to_owned()), ..MacFilter::default() }).is_empty());
    assert_eq!(f(MacFilter { class: Some(MacClass::Unicast), ..MacFilter::default() }).len(), 5);
    assert_eq!(
        f(MacFilter { class: Some(MacClass::Local), ..MacFilter::default() }),
        vec!["52:55:0a:00:02:01"]
    );
    assert_eq!(
        f(MacFilter { class: Some(MacClass::Group), ..MacFilter::default() }),
        vec!["ff:ff:ff:ff:ff:ff"]
    );
    assert_eq!(
        f(MacFilter { vendor: Some(VendorKey::Named("Cisco Systems, Inc".to_owned())), ..MacFilter::default() }),
        vec!["08:00:27:00:00:03"]
    );
    assert_eq!(
        f(MacFilter { vendor: Some(VendorKey::Unknown), ..MacFilter::default() }),
        vec!["00:ff:ff:00:00:05"]
    );
    assert_eq!(
        f(MacFilter { vendor: Some(VendorKey::Local), ..MacFilter::default() }),
        vec!["52:55:0a:00:02:01"]
    );
    assert_eq!(
        f(MacFilter { vlan: Some("10".to_owned()), ..MacFilter::default() }),
        vec!["52:55:0a:00:02:01"]
    );
}

#[test]
fn time_range_keeps_overlapping_rows_with_session_counters() {
    let conn = db();
    sample(&conn);
    // [250, 320): .02 (300..400), .03 (150..350) and the broadcast (100..600).
    let range = TimeRange::new(250, 320);
    let filter = MacFilter { range, ..MacFilter::default() };
    assert_eq!(
        macs(&conn, &filter, MacSort::Mac),
        vec!["08:00:27:00:00:02", "08:00:27:00:00:03", "ff:ff:ff:ff:ff:ff"]
    );
    let page = macs_page(&conn, &filter, MacSort::Frames, &PageRequest::first(1)).unwrap();
    assert_eq!(page.items[0].frames_sent, 30);
    let c = counts(&conn, range).unwrap();
    assert_eq!((c.macs, c.unicast, c.local, c.group, c.vendors), (3, 2, 0, 1, 2));
    let v = vendor_counts(&conn, 10, range).unwrap();
    assert_eq!(
        v,
        vec![
            (VendorKey::Named("Cisco Systems, Inc".to_owned()), 1),
            (VendorKey::Named("PCS Systemtechnik GmbH".to_owned()), 1),
        ]
    );
    // A disjoint range: nothing, never an error.
    let none = TimeRange::new(10_000, 20_000);
    assert_eq!(count_macs(&conn, &MacFilter { range: none, ..MacFilter::default() }).unwrap(), 0);
    assert_eq!(counts(&conn, none).unwrap(), EthCounts::default());
}

#[test]
fn vendor_bars_group_local_and_unknown() {
    let conn = db();
    sample(&conn);
    let v = vendor_counts(&conn, 10, None).unwrap();
    assert_eq!(
        v,
        vec![
            (VendorKey::Named("PCS Systemtechnik GmbH".to_owned()), 2),
            (VendorKey::Named("Cisco Systems, Inc".to_owned()), 1),
            (VendorKey::Unknown, 1),
            (VendorKey::Local, 1),
        ]
    );
    assert_eq!(vendor_counts(&conn, 1, None).unwrap().len(), 1);
    let c = counts(&conn, None).unwrap();
    assert_eq!((c.macs, c.unicast, c.local, c.group, c.vendors), (6, 5, 1, 1, 2));
}

fn pair(src: u8, dst: u8, frames: u64, ts: (i64, i64), types: &[i32], vlans: &[&str]) -> EthernetRow {
    EthernetRow::Pair(EthPairRow {
        src: [0x08, 0x00, 0x27, 0, 0, src],
        dst: [0x08, 0x00, 0x27, 0, 0, dst],
        frames,
        bytes: frames * 64,
        first_ts: ts.0,
        last_ts: ts.1,
        ethertypes: types.to_vec(),
        vlans: vlans.iter().map(|v| (*v).to_owned()).collect(),
    })
}

fn pairs(conn: &Connection, filter: &PairFilter, sort: PairSort) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut request = PageRequest::first(2);
    loop {
        let page = pairs_page(conn, filter, sort, &request).unwrap();
        out.extend(page.items.into_iter().map(|e| (e.src.mac, e.dst.mac)));
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => break,
        }
    }
    out
}

#[test]
fn pairs_merge_filter_and_page() {
    let conn = db();
    sample(&conn);
    insert(&conn, pair(1, 2, 5, (100, 150), &[0x0800], &[]));
    insert(&conn, pair(1, 2, 5, (120, 180), &[0x86dd, 0x0800], &["10"]));
    insert(&conn, pair(2, 1, 3, (300, 310), &[0x0800], &[]));
    insert(&conn, pair(3, 1, 20, (160, 170), &[0x88cc], &[]));
    insert(&conn, pair(3, 2, 1, (390, 395), &[0x42], &["100.20"]));

    let page = pairs_page(&conn, &PairFilter::default(), PairSort::Frames, &PageRequest::first(10)).unwrap();
    assert_eq!(page.items.len(), 4);
    let top = &page.items[0];
    assert_eq!((top.src.mac.as_str(), top.frames), ("08:00:27:00:00:03", 20));
    assert_eq!(top.src.vendor.as_deref(), Some("Cisco Systems, Inc"));
    let merged = &page.items[1];
    assert_eq!((merged.frames, merged.bytes), (10, 640));
    assert_eq!((merged.first_ts, merged.last_ts), (100, 180));
    assert_eq!(merged.ethertypes, vec![0x0800, 0x86dd]);
    assert_eq!(merged.vlans, vec!["10".to_owned()]);

    let all = PairFilter::default();
    assert_eq!(pairs(&conn, &all, PairSort::Frames).len(), 4);
    assert_eq!(pairs(&conn, &all, PairSort::FirstSeen)[0].0, "08:00:27:00:00:01");
    assert_eq!(pairs(&conn, &all, PairSort::LastSeen)[0].1, "08:00:27:00:00:02");
    assert_eq!(count_pairs(&conn, &all).unwrap(), 4);

    let by = |f: PairFilter| pairs(&conn, &f, PairSort::Frames).len();
    assert_eq!(by(PairFilter { mac: Some("08-00-27-00-00-03".to_owned()), ..PairFilter::default() }), 2);
    assert_eq!(by(PairFilter { mac: Some("08:00:27:00:00:01".to_owned()), ..PairFilter::default() }), 3);
    assert_eq!(by(PairFilter { q: Some("cisco".to_owned()), ..PairFilter::default() }), 2);
    assert_eq!(count_pairs(&conn, &PairFilter { q: Some("cisco".to_owned()), ..PairFilter::default() }).unwrap(), 2);
    assert_eq!(by(PairFilter { vlan: Some("100.20".to_owned()), ..PairFilter::default() }), 1);
    assert_eq!(by(PairFilter { ethertype: Some(0x86dd), ..PairFilter::default() }), 1);
    assert_eq!(by(PairFilter { range: TimeRange::new(300, 391), ..PairFilter::default() }), 2);
}

#[test]
fn ethertypes_and_vlans() {
    let conn = db();
    let v = |frames, first, last| EthVolume { frames, bytes: frames * 60, first_ts: first, last_ts: last };
    insert(&conn, EthernetRow::Type(0x0800, v(10, 1, 50)));
    insert(&conn, EthernetRow::Type(0x0800, v(5, 0, 40)));
    insert(&conn, EthernetRow::Type(0x42, v(2, 60, 70)));
    insert(&conn, EthernetRow::Type(-1, v(1, 5, 5)));
    let t = ethertypes(&conn, None).unwrap();
    assert_eq!(t.iter().map(|e| e.ethertype).collect::<Vec<_>>(), vec![0x0800, 0x42, -1]);
    assert_eq!((t[0].volume.frames, t[0].volume.first_ts, t[0].volume.last_ts), (15, 0, 50));
    assert_eq!(ethertypes(&conn, TimeRange::new(55, 100)).unwrap().len(), 1);

    let vlan = |ids: &[u16], tpid, frames| EthernetRow::Vlan(EthVlanRow { ids: ids.to_vec(), outer_tpid: tpid, volume: v(frames, 10, 20) });
    insert(&conn, vlan(&[10], 0x8100, 4));
    insert(&conn, vlan(&[100, 20], 0x8100, 1));
    insert(&conn, vlan(&[100, 20], 0x88a8, 1));
    let l = vlans(&conn, None).unwrap();
    assert_eq!(l.len(), 2);
    assert_eq!((l[0].stack.as_str(), l[0].depth, l[0].outer_tpid), ("10", 1, 0x8100));
    let q = &l[1];
    assert_eq!((q.stack.as_str(), q.outer_id, q.inner_id, q.depth), ("100.20", 100, 20, 2));
    assert_eq!((q.outer_tpid, q.volume.frames), (0x88a8, 2));
    let c = counts(&conn, None).unwrap();
    assert_eq!((c.frames, c.bytes, c.vlans, c.tagged_frames), (18, 1080, 2, 6));
    // A stack without identifier is ignored.
    insert(&conn, vlan(&[], 0x8100, 1));
    assert_eq!(vlans(&conn, None).unwrap().len(), 2);
}

#[test]
fn module_count_over_a_range() {
    let conn = db();
    sample(&conn);
    let n = crate::range::ModuleRows::EthernetMacs
        .count(&conn, TimeRange::new(250, 320).unwrap())
        .unwrap();
    assert_eq!(n, 3);
}
