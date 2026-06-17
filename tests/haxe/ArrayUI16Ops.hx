class ArrayUI16Ops {
    static function main() {
        var a:Array<hl.UI16> = [1, 2, 3];
        var i = 1;
        var x = a[i];
        a[i] = 4;
        trace(x);
        trace(a);
    }
}
