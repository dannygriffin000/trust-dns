// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::iter::Chain;

use trust_dns::rr::Record;

use store::sqlite::{LookupRecords, LookupRecordsIter};

/// The result of a lookup on an Authority
///
/// # Lifetimes
///
/// * `'c` - the catalogue lifetime
/// * `'r` - the recordset lifetime, subset of 'c
/// * `'q` - the queries lifetime
#[derive(Debug)]
pub enum AuthLookup {
    /// There is no matching name for the query
    NxDomain,
    /// There are no matching records for the query, but there are others associated to the name
    NameExists,
    /// The request was refused, eg AXFR is not supported
    Refused,
    // TODO: change the result of a lookup to a set of chained iterators...
    /// Records
    Records(LookupRecords),
    /// Soa only differs from Records in that the lifetime on the name is from the authority, and not the query
    SOA(LookupRecords),
    /// An axfr starts with soa, chained to all the records, then another soa...
    AXFR {
        /// The first SOA record in an AXFR response
        start_soa: LookupRecords,
        /// The records to return
        records: LookupRecords,
        /// The last SOA record of an AXFR (matches the first)
        end_soa: LookupRecords,
    },
}

impl AuthLookup {
    /// Returns true if either the associated Records are empty, or this is a NameExists or NxDomain
    pub fn is_empty(&self) -> bool {
        match *self {
            AuthLookup::NameExists | AuthLookup::NxDomain | AuthLookup::Refused => true,
            AuthLookup::Records(_) | AuthLookup::SOA(_) | AuthLookup::AXFR { .. } => false,
        }
    }

    /// This is a non-existant domain name
    pub fn is_nx_domain(&self) -> bool {
        match *self {
            AuthLookup::NxDomain => true,
            _ => false,
        }
    }

    /// This is a non-existant domain name
    pub fn is_refused(&self) -> bool {
        match *self {
            AuthLookup::Refused => true,
            _ => false,
        }
    }

    /// Conversion to an iterator
    pub fn iter(&self) -> AuthLookupIter {
        self.into_iter()
    }

    /// Does not panic, but will return no records if it is not of that type
    pub fn unwrap_records(self) -> LookupRecords {
        match self {
            AuthLookup::Records(records) => records,
            _ => LookupRecords::default(),
        }
    }
}

impl Default for AuthLookup {
    fn default() -> Self {
        AuthLookup::NxDomain
    }
}

impl<'a> IntoIterator for &'a AuthLookup {
    type Item = &'a Record;
    type IntoIter = AuthLookupIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            AuthLookup::NxDomain | AuthLookup::NameExists | AuthLookup::Refused => {
                AuthLookupIter::Empty
            }
            AuthLookup::Records(r) | AuthLookup::SOA(r) => AuthLookupIter::Records(r.into_iter()),
            AuthLookup::AXFR {
                start_soa,
                records,
                end_soa,
            } => AuthLookupIter::AXFR(start_soa.into_iter().chain(records).chain(end_soa)),
        }
    }
}

/// An iterator over an Authority Lookup
pub enum AuthLookupIter<'r> {
    /// The empty set
    Empty,
    /// An iteration over a set of Records
    Records(LookupRecordsIter<'r>),
    /// An iteration over an AXFR
    AXFR(Chain<Chain<LookupRecordsIter<'r>, LookupRecordsIter<'r>>, LookupRecordsIter<'r>>),
}

impl<'r> Iterator for AuthLookupIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            AuthLookupIter::Empty => None,
            AuthLookupIter::Records(i) => i.next(),
            AuthLookupIter::AXFR(i) => i.next(),
        }
    }
}

impl<'a> Default for AuthLookupIter<'a> {
    fn default() -> Self {
        AuthLookupIter::Empty
    }
}

impl From<LookupRecords> for AuthLookup {
    fn from(lookup: LookupRecords) -> Self {
        AuthLookup::Records(lookup)
    }
}
