// Targets CallMethod (virtual dispatch on a base-typed reference) and
// CallThis (a method calling another method on itself via `this`).
class MethodBase {
    public function new() {}

    public function compute(x:Int):Int {
        return this.helper(x) + 1;
    }

    public function helper(x:Int):Int {
        return x * 2;
    }
}

class MethodChild extends MethodBase {
    public function new() { super(); }

    override public function helper(x:Int):Int {
        return x * 3;
    }
}

class MethodCalls {
    public static function main() {
        var obj:MethodBase = new MethodChild();
        // virtual dispatch -> CallMethod
        var r = obj.compute(10);
        trace(r);
    }
}
