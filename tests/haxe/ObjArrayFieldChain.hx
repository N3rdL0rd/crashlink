typedef Item = { var val: Int; var nested: Array<Int>; };

class ObjArrayFieldChain {
    static function main() {
        var items: Array<Item> = [
            { val: 1, nested: [10, 20, 30] },
            { val: 2, nested: [40, 50, 60] },
        ];
        var i = 1;
        trace(items[i].nested[2]);
        items[i].nested[0] = 999;
        trace(items[0].nested[0]);
        trace(items[i].nested[0]);
        trace(items[i].val + items[i].nested[1]);
    }
}
