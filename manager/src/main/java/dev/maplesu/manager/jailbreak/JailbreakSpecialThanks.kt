package dev.maplesu.manager.jailbreak

import androidx.annotation.StringRes
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.sp
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.screen.home.specialThanksText
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun JailbreakSpecialThanks(
    modifier: Modifier = Modifier,
    @StringRes textRes: Int = R.string.maplesu_jailbreak_98260_credit,
) {
    val text = stringResource(textRes)
    when (LocalUiMode.current) {
        UiMode.Material -> androidx.compose.material3.Text(
            text = specialThanksText(text, MaterialTheme.colorScheme.primary),
            modifier = modifier,
            style = MaterialTheme.typography.bodyMedium,
        )
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.Text(
            text = specialThanksText(text, MiuixTheme.colorScheme.primary),
            modifier = modifier,
            fontSize = 14.sp,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
    }
}
