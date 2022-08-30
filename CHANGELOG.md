# Release Notes

All notable changes to this project will be documented in this file.

## Version: 1.11.3

### Bugfixes

- Fixed bug in 'deserialize_cells_tree_inmem_with_abort' - deleted unneded check with error (all needed checks performs in 'precheck_cells_tree_len'). Error appeared when BOC contained CRC.
- Fixed bug in 'deserialize_cells_tree_inmem_with_abort' - CRC calculated using wrong offsets.