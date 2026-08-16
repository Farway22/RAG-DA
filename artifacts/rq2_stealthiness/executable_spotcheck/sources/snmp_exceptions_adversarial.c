#include <stdio.h>

#define TSRMLS_DC
#define SUCCESS 0
#define IS_LONG 1
typedef struct { int type; long lval; } zval;
typedef struct { long exceptions_enabled; } php_snmp_object;
#define Z_TYPE_P(value) ((value)->type)
#define Z_LVAL_P(value) ((value)->lval)
static void zval_copy_ctor(zval *value) { (void)value; }
static void convert_to_long(zval *value) { value->type = IS_LONG; }
static void zval_dtor(zval *value) { (void)value; }

static int php_snmp_write_exceptions_enabled(php_snmp_object *snmp_object, zval *newval TSRMLS_DC) { zval ztmp; int res = SUCCESS; if (Z_TYPE_P(newval) != IS_LONG) { ztmp = *newval; zval_copy_ctor(&ztmp); convert_to_long(&ztmp); newval = &ztmp; } snmp_object->exceptions_enabled = Z_LVAL_P(newval); if (newval == &ztmp) { zval_dtor(newval); } return res; }

int main(void) {
    php_snmp_object object = {0};
    zval direct = {IS_LONG, 5};
    zval converted = {0, 9};
    int first = php_snmp_write_exceptions_enabled(&object, &direct);
    printf("%d:%ld\n", first, object.exceptions_enabled);
    int second = php_snmp_write_exceptions_enabled(&object, &converted);
    printf("%d:%ld\n", second, object.exceptions_enabled);
    return 0;
}
