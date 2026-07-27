class Item {
    public var value:Int;
    public function new(value:Int) {
        this.value = value;
    }
}

class HeapsObjArrayFieldIndex {
    var items:Array<Item>;

    public function new(items:Array<Item>) {
        this.items = items;
    }

    public function at(i:Int):Int {
        return items[i].value;
    }

    static function main() {
        var c = new HeapsObjArrayFieldIndex([new Item(10), new Item(20), new Item(30)]);
        trace(c.at(1));
    }
}
