class StaticInstanceCollide {
    var val:Int;
    public function new(v:Int) { val = v; }
    public function greet():String { return "instance:" + val; }
    public static function greetStatic():String { return "static"; }

    static function main() {
        var o = new StaticInstanceCollide(5);
        Sys.println(o.greet());
        Sys.println(StaticInstanceCollide.greetStatic());

        var it = new CustomIter(3);
        var out = "";
        for (v in it) out += v + ",";
        Sys.println(out);
    }
}

class CustomIter {
    var n:Int;
    var i:Int = 0;
    public function new(n:Int) { this.n = n; }
    public function hasNext():Bool { return i < n; }
    public function next():Int { return i++; }
}
