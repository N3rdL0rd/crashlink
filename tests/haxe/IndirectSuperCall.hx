class IndirectBase {
    public function new() {}
    public function greet(): String {
        return "base";
    }
}

class IndirectSub extends IndirectBase {
    public function new() { super(); }
    override public function greet(): String {
        return "sub";
    }
    public function greetViaSuper(): String {
        return super.greet() + "-indirect";
    }
}

class IndirectSuperCall {
    static function main() {
        var s = new IndirectSub();
        trace(s.greet());
        trace(s.greetViaSuper());
    }
}
