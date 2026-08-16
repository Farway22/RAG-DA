#include <stdio.h>

typedef int gint;
typedef struct { int unused; } tvbuff_t;
typedef struct { int unused; } packet_info;
typedef struct { int unused; } proto_tree;
typedef struct { int unused; } wccp_address_table;
static int noted_length = -1;
#define NOTE_EATEN_LENGTH(value) do { noted_length = (value); } while (0)

static int dissect_wccp2_mask_value_set_list(
    tvbuff_t *tvb, int offset, int length, packet_info *pinfo,
    proto_tree *tree, wccp_address_table *table) {
    (void)tvb; (void)pinfo; (void)tree; (void)table;
    return offset + length;
}

static gint dissect_wccp2_assignment_map(tvbuff_t *tvb, int offset, int length_count, packet_info *pinfo, proto_tree *info_tree, wccp_address_table* addr_table) { gint new_length; new_length=dissect_wccp2_mask_value_set_list(tvb, offset, length_count, pinfo, info_tree, addr_table); NOTE_EATEN_LENGTH(new_length); return length_count; }

int main(void) {
    tvbuff_t tvb = {0}; packet_info pinfo = {0};
    proto_tree tree = {0}; wccp_address_table table = {0};
    const int lengths[] = {0, 7, 31};
    for (int i = 0; i < 3; ++i) {
        int result = dissect_wccp2_assignment_map(
            &tvb, 5, lengths[i], &pinfo, &tree, &table);
        printf("%d:%d\n", result, noted_length);
    }
    return 0;
}
