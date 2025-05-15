import haxe.io.Bytes;

class TestClass {
    public var test: Int = 5;

    public function new() {}
}

class PatchMe {
    static function main() {
        var val = 1.0;
        var val2 = 2.0;
        thing(val, val2, "Unpatched message!", new TestClass());
    }

    static function thing(val: Float, val2: Float, msg: String, val3: TestClass) {
        if (val == 2.0) {
            trace(msg);
            trace(val3.test);
        } else {
            trace("Patch failed!");
        }
    }
}