use std::iter;

/// Sort a list of domains into *domain order*. Domain order is computed by splitting the inputs
/// into dot-seperated segments, and comparing each segment.
pub fn sort(domains: &mut [String]) {
    domains.sort_by(|a, b| {
        for (a_part, b_part) in iter::zip(a.rsplit('.'), b.rsplit('.')) {
            let order = a_part.partial_cmp(b_part).unwrap();
            if order.is_ne() {
                return order;
            }
        }
        assert_eq!(a, b);
        a.partial_cmp(b).unwrap()
    });
    domains.reverse();
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn varying_domains() {
        let mut doms: Vec<String> = vec![
            "a.abc",
            "*.hackattack.com.admin-mcas-df.ms",
            "*.hackattack.com.admin-us3.cas.ms",
            "*.hackattack.com.admin-eu2.cas.ms",
            "*.hackattack.com.admin-us2.cas.ms",
            "*.hackattack.com.admin-eu.cas.ms",
            "*.hackattack.com.admin-us.cas.ms",
            "*.hackattack.com.admin-mcas.ms",
            "*.hackattack.com.mcas-df.ms",
            "*.hackattack.com.us3.cas.ms",
            "*.hackattack.com.eu2.cas.ms",
            "*.hackattack.com.us2.cas.ms",
            "*.hackattack.com.eu.cas.ms",
            "*.hackattack.com.us.cas.ms",
            "*.hackattack.com.mcas.ms",
            "*.mcas.ms",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        sort(&mut doms);
        assert_eq!(
            doms,
            vec![
                "*.hackattack.com.mcas-df.ms",
                "*.hackattack.com.mcas.ms",
                "*.mcas.ms",
                "*.hackattack.com.us3.cas.ms",
                "*.hackattack.com.us2.cas.ms",
                "*.hackattack.com.us.cas.ms",
                "*.hackattack.com.eu2.cas.ms",
                "*.hackattack.com.eu.cas.ms",
                "*.hackattack.com.admin-us3.cas.ms",
                "*.hackattack.com.admin-us2.cas.ms",
                "*.hackattack.com.admin-us.cas.ms",
                "*.hackattack.com.admin-eu2.cas.ms",
                "*.hackattack.com.admin-eu.cas.ms",
                "*.hackattack.com.admin-mcas-df.ms",
                "*.hackattack.com.admin-mcas.ms",
                "a.abc"
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
        )
    }
}
