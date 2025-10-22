// If you're confused - that's okay! I am too!
// This test file exists as a test for both pyhl and hlmod. It was backported here for convenience.

import haxe.io.Bytes;

class SuperTestClass {
    public static var STATIC_VAL: Int = 8;

    public function do_a_thing() {
        trace("Hello world! superclass");
    }
}

class TestClass extends SuperTestClass {
    public var test: Int = 5;

    public function new() {}

    public override function do_a_thing() {
        trace("Hello world! subclass");
    }
}

class PatchMe {
    static function main() {
        var val = get_value();
        var val2 = 2.0;
        thing(val, val2, "Unpatched message!", new TestClass());
        array_test();
        trace(SuperTestClass.STATIC_VAL);
    }

    static function array_test() {
        arraybytes_consumer([1, 2, 3]);
        arrayobj_consumer([new TestClass(), new TestClass(), new TestClass()]);
    }

    static function arraybytes_consumer(test: Array<Int>) {
        trace(test);
    }

    static function arrayobj_consumer(test: Array<TestClass>) {
        trace(test);
    }

    static function get_value(): Float {
        return 1.0;
    }

    static function thing(val: Float, val2: Null<Float>, msg: String, val3: Null<TestClass>) {
        if (val == 2.0) {
            trace(msg);
            trace(val3.test);
        } else {
            trace("Patch failed!");
        }
    }
}