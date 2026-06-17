class ArrayBoundsConst {
    static function make() {
        return [10, 20, 30];
    }

    static function main() {
        var a = make();
        var x = a[0];
        var y = a[2];
        trace(x);
        trace(y);
    }
}
