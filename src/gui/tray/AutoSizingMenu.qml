import QtQuick 2.15
import QtQuick.Controls 2.3
import Style 1.0

Menu {
    background: Rectangle {
        border.color: palette.dark
        color: palette.base
    }

    width: {
        var result = 0;
        var padding = 0;
        for (var i = 0; i < count; ++i) {
            var item = itemAt(i);
            result = Math.max(item.contentItem.implicitWidth, result);
            padding = Math.max(item.padding, padding);
        }
        return result + padding * 2;
    }
}
