class Pair<T> {
    public var lo:T;
    public var hi:T;

    public function new(lo:T, hi:T) {
        this.lo = lo;
        this.hi = hi;
    }

    public function pick(first:Bool):T {
        if (first) {
            return lo;
        }
        return hi;
    }
}

class GenMethodArg {
    static function main() {
        var p = new Pair<Int>(1, 2);
        Sys.println(p.pick(true));
    }
}
