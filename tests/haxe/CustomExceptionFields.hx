class DataError extends haxe.Exception {
    public var code:Int;
    public var payload:String;

    public function new(msg:String, code:Int, payload:String) {
        super(msg);
        this.code = code;
        this.payload = payload;
    }
}

class CustomExceptionFields {
    static function risky(n:Int):Int {
        if (n < 0) throw new DataError("negative", 42, "bad-" + n);
        return n * 2;
    }

    static function main() {
        try {
            risky(-5);
        } catch (e:DataError) {
            trace(e.message);
            trace(e.code);
            trace(e.payload);
        }
        trace(risky(3));
    }
}
