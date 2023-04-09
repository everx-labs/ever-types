# Release Notes

All notable changes to this project will be documented in this file.

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