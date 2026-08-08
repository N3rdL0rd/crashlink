class PropertyBackingField {
    var _val:Int;
    public var val(get, set):Int;

    public function new(v:Int) { _val = v; }

    function get_val():Int {
        Sys.println("getter called");
        return _val;
    }

    function set_val(v:Int):Int {
        Sys.println("setter called");
        _val = v * 2;
        return _val;
    }

    static function main() {
        var p = new PropertyBackingField(3);
        Sys.println(p.val);
        p.val = 10;
        Sys.println(p.val);
        p.val += 1;
        Sys.println(p.val);
        Sys.println(p._val);
    }
}
