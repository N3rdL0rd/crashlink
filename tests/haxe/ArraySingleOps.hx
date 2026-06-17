class ArraySingleOps {
    static function main() {
        var a:Array<Single> = [1.0, 2.0, 3.0];
        var i = 1;
        var x = a[i];
        a[i] = 4.0;
        trace(x);
        trace(a);
    }
}
