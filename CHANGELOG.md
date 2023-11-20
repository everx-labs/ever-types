# Release Notes

All notable changes to this project will be documented in this file.

## Version 2.0.31

- Add BLS KeyOption from ever-crypto

## Version 2.0.30

- Fixed performance issue with fake 16MB big cell

## Version 2.0.29

- Remove BuilderData::level_mask (compute it at finalization)

## Version 2.0.28

- Fixed persistant state save

## Version 2.0.27

- Make SliceData::with_bitstring() public

## Version 2.0.26

- Optimize hashmap labels

## Version 2.0.25

- Optimize put_to_fork_with_mode()

## Version 2.0.24

- Add BocWriterStack for faster boc saving

## Version 2.0.23

- Add crypto wrappers

## Version 2.0.22

- Transform BocWriter::traverse() into iterative algo

## Version 2.0.21

- Refactor hashmap functions to optimize perfomance

## Version 2.0.20

- Add hashmap benchmark with profiling instructions

## Version 2.0.19

- Upgraded to ed25519-dalek 2.0

## Version 2.0.18

- Fixed big cells counting in read_inmem

## Version 2.0.17

- Additional checks for big cells count while BOC reading

## Version 2.0.16

- Removal of dead code

## Version 2.0.15

- BocWriter::write_ex(): do not compute CRC if not requested

## Version 2.0.14

- Fixed cells lifetime while BOC traverse

## Version 2.0.13

- Added UsageTree::build_visited_set

## Version 2.0.12

- Refactor LabelReader for perfomance
- Use load_bitstring for performance

## Version 2.0.11

- Use SliceData as bitstring for hashmap key manipulation

## Version 2.0.10


- Fixed BocReader::read_inmem for big bocs (> 4Gb)

## Version 2.0.9

- Optimize Cell::default()

## Version 2.0.8

- Fixed bug in hashmap_filter function

## Version 2.0.7

- Fixed panics after fuzzing

## Version 2.0.6

- Enhanced hashmap filter split

## Version 2.0.5

- Enhanced hashmap split by prefix
- Enhanced hashmap merge in any place
- Implemented hashmap filter split in one pass like two hashmap filters

## Version 2.0.4

- Fixed bug in x25519_shared_secret

## Version 2.0.3

- Added interface base64_encode_url_safe
- Minor refactoring

## Version 2.0.2

- Moved all crypto crates to wrappers

## Version 2.0.1

- Added crypto functions from crypto-repo
- Added wrappers for sha256, sha512, base64
- Bumped version of crc crate to 3.0
- Fix for clippy

## Version 2.0.0
- Added big cell. Call `create_big_cell` to create one.
- BOC routines: supported big cells and refactoring. 
  Created two basic structs for in-depth working with BOC: `BocWriter` and `BocReader`.
  Additionally three convinient wrappers: `write_boc`, `read_boc` and `read_single_root_boc`, that you'll probably want to use.

## Version: 1.12.2
- Fix for clippy

## Version: 1.12.1
- Add common as submodule

## Version: 1.12.0
- Remove bad types conversion

## Version: 1.11.11

### Bugfixes
- Loading cells with checking cell type

## Version: 1.11.3

### Bugfixes

- Fixed bug in 'deserialize_cells_tree_inmem_with_abort' - deleted unneded check with error (all needed checks performs in 'precheck_cells_tree_len'). Error appeared when BOC contained CRC.
- Fixed bug in 'deserialize_cells_tree_inmem_with_abort' - CRC calculated using wrong offsets.