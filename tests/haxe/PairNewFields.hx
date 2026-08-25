class Box {
    public var v:Int;
    public function new(v:Int) {
        this.v = v;
    }
}

class Pair {
    public var a:Box;
    public var b:Box;
    public function new() {
        a = new Box(1);
        b = new Box(2);
    }
}

class PairNewFields {
    static function main() {
        var p = new Pair();
        p.a.v = 100;
        Sys.println(p.a.v);
        Sys.println(p.b.v);
        if (p.a == p.b) {
            Sys.println("ALIASED-BUG");
        } else {
            Sys.println("distinct-ok");
        }
    }
}
