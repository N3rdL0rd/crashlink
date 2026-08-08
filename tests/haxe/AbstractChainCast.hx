abstract A(Int) {
    public inline function new(v:Int) this = v;
    @:to public inline function toB():B return new B(this * 2);
}

abstract B(Int) {
    public inline function new(v:Int) this = v;
    @:to public inline function toC():C return new C(this + 1);
    public function get():Int return this;
}

abstract C(String) {
    public inline function new(v:Int) this = "c" + v;
    public function get():String return this;
}

class AbstractChainCast {
    static function takesC(c:C):String return c.get();

    static function main() {
        var a = new A(5);
        var b:B = a; // implicit cast A -> B
        var c:C = b; // implicit cast B -> C
        Sys.println(c.get());
        Sys.println(takesC(b));
    }
}
