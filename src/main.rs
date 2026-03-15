use crate::utils::MapInfo;

mod utils;

fn main() {
    let maps = MapInfo::Scan("self");
    for s in maps {
        println!("{:?}", s);
    }
}
