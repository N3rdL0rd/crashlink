class PatchMe {
    static function main() {
        var val = 1.0;
        var val2 = 2.0;
        thing(val, val2, "Unpatched message!");
    }

    static function thing(val: Float, val2: Float, msg: String) {
        if (val == 2.0) {
            trace(msg);
        } else {
            trace("Patch failed!");
        }
    }
}