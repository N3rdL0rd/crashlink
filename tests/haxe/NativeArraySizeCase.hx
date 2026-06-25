class NativeArraySizeCase {
    static function getCount(): Int {
        return 3;
    }
    static function make(): Int {
        var arr = new hl.NativeArray<Int>(getCount());
        return arr.length;
    }
    static function main() {
        trace(make());
    }
}
