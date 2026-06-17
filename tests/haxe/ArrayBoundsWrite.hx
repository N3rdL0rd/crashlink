class ArrayBoundsWrite {
    static function main() {
        var a = [10, 20, 30];
        a[0] = 99;
        a[2] = a[1];
        trace(a);
    }
}
