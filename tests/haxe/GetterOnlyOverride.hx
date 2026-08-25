class Base {
    public var val(get, never):Int;
    public function new() {}
    function get_val():Int { return 1; }
}

class Sub extends Base {
    public function new() { super(); }
    override function get_val():Int { return super.get_val() + 100; }
}

class GetterOnlyOverride {
    static function main() {
        var b:Base = new Sub();
        trace(b.val);
        var s = new Sub();
        trace(s.val);
        var base = new Base();
        trace(base.val);
    }
}
