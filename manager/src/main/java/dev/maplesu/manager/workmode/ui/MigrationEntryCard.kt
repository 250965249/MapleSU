package dev.maplesu.manager.workmode.ui

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.material.SegmentedColumn
import com.maplesu.core.ui.component.material.SegmentedListItem
import top.yukonga.miuix.kmp.basic.Card as MiuixCard
import top.yukonga.miuix.kmp.preference.ArrowPreference

/**
 * 首页的迁移入口卡：一句话说明 + 进入迁移页。目标模式、备份、确认都在迁移页里完成。
 * 由调用方决定是否显示；未检测到外部 Root 时不渲染。
 */
@Composable
fun MigrationEntryCard(
    onOpenFullPage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val title = stringResource(R.string.migration_entry_title)
    val summary = stringResource(R.string.migration_entry_summary)
    when (LocalUiMode.current) {
        UiMode.Miuix -> MiuixCard(modifier = modifier.fillMaxWidth()) {
            ArrowPreference(title = title, summary = summary, onClick = onOpenFullPage)
        }

        UiMode.Material -> SegmentedColumn(
            modifier = modifier.fillMaxWidth(),
            content = listOf {
                SegmentedListItem(
                    onClick = onOpenFullPage,
                    headlineContent = { Text(title) },
                    supportingContent = { Text(summary) },
                    trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null) },
                )
            },
        )
    }
}
