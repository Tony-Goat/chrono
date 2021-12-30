// Copyright 2012-2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::Tm;
use libc::{self, time_t};
use std::io;
use std::mem;

#[cfg(any(target_os = "solaris", target_os = "illumos"))]
extern "C" {
    static timezone: time_t;
    static altzone: time_t;
}

#[cfg(any(target_os = "solaris", target_os = "illumos"))]
fn tzset() {
    extern "C" {
        fn tzset();
    }
    unsafe { tzset() }
}

fn rust_tm_to_tm(rust_tm: &Tm, tm: &mut libc::tm) {
    tm.tm_sec = rust_tm.tm_sec;
    tm.tm_min = rust_tm.tm_min;
    tm.tm_hour = rust_tm.tm_hour;
    tm.tm_mday = rust_tm.tm_mday;
    tm.tm_mon = rust_tm.tm_mon;
    tm.tm_year = rust_tm.tm_year;
    tm.tm_wday = rust_tm.tm_wday;
    tm.tm_yday = rust_tm.tm_yday;
    tm.tm_isdst = rust_tm.tm_isdst;
}

fn tm_to_rust_tm(tm: &libc::tm, utcoff: i32, rust_tm: &mut Tm) {
    rust_tm.tm_sec = tm.tm_sec;
    rust_tm.tm_min = tm.tm_min;
    rust_tm.tm_hour = tm.tm_hour;
    rust_tm.tm_mday = tm.tm_mday;
    rust_tm.tm_mon = tm.tm_mon;
    rust_tm.tm_year = tm.tm_year;
    rust_tm.tm_wday = tm.tm_wday;
    rust_tm.tm_yday = tm.tm_yday;
    rust_tm.tm_isdst = tm.tm_isdst;
    rust_tm.tm_utcoff = utcoff;
}

#[cfg(any(target_os = "nacl", target_os = "solaris", target_os = "illumos"))]
unsafe fn timegm(tm: *mut libc::tm) -> time_t {
    use std::env::{remove_var, set_var, var_os};
    extern "C" {
        fn tzset();
    }

    let ret;

    let current_tz = var_os("TZ");
    set_var("TZ", "UTC");
    tzset();

    ret = libc::mktime(tm);

    if let Some(tz) = current_tz {
        set_var("TZ", tz);
    } else {
        remove_var("TZ");
    }
    tzset();

    ret
}

pub fn time_to_local_tm(sec: i64, tm: &mut Tm) {
    unsafe {
        let sec = sec as time_t;
        let mut out = mem::zeroed();
        if libc::localtime_r(&sec, &mut out).is_null() {
            panic!("localtime_r failed: {}", io::Error::last_os_error());
        }
        #[cfg(any(target_os = "solaris", target_os = "illumos"))]
        let gmtoff = {
            tzset();
            // < 0 means we don't know; assume we're not in DST.
            if out.tm_isdst == 0 {
                // timezone is seconds west of UTC, tm_gmtoff is seconds east
                -timezone
            } else if out.tm_isdst > 0 {
                -altzone
            } else {
                -timezone
            }
        };
        #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
        let gmtoff = out.tm_gmtoff;
        tm_to_rust_tm(&out, gmtoff as i32, tm);
    }
}

pub fn utc_tm_to_time(rust_tm: &Tm) -> i64 {
    #[cfg(not(any(
        all(target_os = "android", target_pointer_width = "32"),
        target_os = "nacl",
        target_os = "solaris",
        target_os = "illumos"
    )))]
    use libc::timegm;
    #[cfg(all(target_os = "android", target_pointer_width = "32"))]
    use libc::timegm64 as timegm;

    let mut tm = unsafe { mem::zeroed() };
    rust_tm_to_tm(rust_tm, &mut tm);
    unsafe { timegm(&mut tm) as i64 }
}

pub fn local_tm_to_time(rust_tm: &Tm) -> i64 {
    let mut tm = unsafe { mem::zeroed() };
    rust_tm_to_tm(rust_tm, &mut tm);
    unsafe { libc::mktime(&mut tm) as i64 }
}

//This implementation is derived from the musl standard library's implementation
type Time = i64;

const SECONDS_PER_DAY: i64 = 60 * 60 * 24;
const DAYS_PER_YEAR: i64 = 365;
const SECONDS_PER_LEAPYEAR: i64 = SECONDS_PER_DAY * (DAYS_PER_YEAR + 1);

const DAYS_PER_400Y: i64 = DAYS_PER_YEAR * 400 + 97;
const DAYS_PER_100Y: i64 = DAYS_PER_YEAR * 100 + 24;
const DAYS_PER_4Y: i64 = DAYS_PER_YEAR * 4 + 1;

//This is the last time a 400 year leapday happened
//94668400 is the Unix timestamp of midnight, January 1st, 2000
const LEAP_EPOCH: i64 = 946684800 + SECONDS_PER_DAY * (31 + 29);

//Months are in the order of March, April, May... January, February
const DAYS_IN_MONTH: [i64; 12] = [31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29];

//Very similar to the POSIX gmtime_r. It takes a reference to a Unix timestamp,
//A mutable reference to a structure to modify, and returns true if there would be
//an overflow and false if the conversion was a success
fn gmtime_rs(t: &Time, tm: &mut Tm) -> bool {
    //Make sure we won't overflow before doing all the calculations
    if *t > i32::MAX as i64 * SECONDS_PER_LEAPYEAR || *t < i32::MIN as i64 * SECONDS_PER_LEAPYEAR {
        return true;
    }

    let mut seconds = t - LEAP_EPOCH;
    let mut days = seconds / SECONDS_PER_DAY;
    let mut remainder_seconds = seconds % SECONDS_PER_DAY;
    if remainder_seconds < 0 {
        remainder_seconds += SECONDS_PER_DAY;
        days -= 1;
    }

    //The leap epoch was on a Wednesday, adjust accordingly
    let mut week_day = (3 + days) % 7;
    if week_day < 0 {
        week_day += 7;
    }

    //Calculate how many four-century cycles there have been
    let mut four_century_cycle = days / DAYS_PER_400Y;
    let mut remainder_days = days % DAYS_PER_400Y;
    if remainder_days < 0 {
        remainder_days += DAYS_PER_400Y;
        four_century_cycle -= 1;
    }

    //Calculate how many century cycles there have been
    let mut century_cycle = remainder_days / DAYS_PER_100Y;
    if century_cycle == 4 {
        century_cycle -= 1;
    }
    remainder_days -= century_cycle * DAYS_PER_100Y;

    //Calculate how many 4 year cycles there have been
    let mut four_year_cycle = remainder_days / DAYS_PER_4Y;
    if four_year_cycle == 25 {
        four_year_cycle -= 1;
    }
    remainder_days -= four_year_cycle * DAYS_PER_4Y;

    //Calculate how many years there have been
    let mut remainder_years = remainder_days / DAYS_PER_YEAR;
    if remainder_years == 4 {
        remainder_years -= 1;
    }
    remainder_days -= remainder_years * DAYS_PER_YEAR;

    //Figure out if it is a leap year. If we have no remaining years after the four year cycle
    //calculation and we're not on a century, we are in a leap year.
    let leap: i64 = if remainder_years == 0 && (four_year_cycle != 0 || century_cycle == 0) {
        1
    } else {
        0
    };
    let mut year_day = remainder_days + 31 + 28 + leap;
    if year_day >= DAYS_PER_YEAR + leap {
        year_day -= DAYS_PER_YEAR + leap;
    }

    //The +100 adjusts the time back to the POSIX standard that says it should be the offset from 1900
    let mut years = remainder_years + (4 * four_year_cycle) + (100 * century_cycle) + (400 * four_century_cycle) + 100;

    //Use the remaining days to figure out which month it is
    let mut month: i64 = 0;
    for i in 0..12 {
        if DAYS_IN_MONTH[i] <= remainder_days {
            remainder_days -= DAYS_IN_MONTH[i];
            month += 1;
        } else {
            break;
        }
    }

    if month >= 10 {
        month -= 12;
        years += 1;
    }

    month += 2;
    remainder_days += 1;

    let hours = remainder_seconds / 3600;
    let minutes = remainder_seconds / 60 % 60;
    seconds = remainder_seconds % 60;

    //This is just in case we were wrong earlier
    if years > i32::MAX as i64 || years < i32::MIN as i64 {
        return true;
    }

    //If not, we can assign everything into the struct provided
    tm.tm_year = years as i32;
    tm.tm_mon = month as i32;
    tm.tm_mday = remainder_days as i32;
    tm.tm_wday = week_day as i32;
    tm.tm_yday = year_day as i32;
    tm.tm_hour = hours as i32;
    tm.tm_min = minutes as i32;
    tm.tm_sec = seconds as i32;
    tm.tm_isdst = 0;
    tm.tm_utcoff = 0;

    return false;
}
