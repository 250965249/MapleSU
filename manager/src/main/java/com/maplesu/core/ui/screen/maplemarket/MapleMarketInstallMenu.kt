package com.maplesu.core.ui.screen.maplemarket

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.widthIn
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.maplesu.core.R

/** The install launcher is a local UI state; opening either destination always closes it. */
@Composable
fun MapleMarketInstallMenu(
    isUltra: Boolean,
    onMarket: () -> Unit,
    onLocalFile: () -> Unit,
    active: Boolean = true,
    modifier: Modifier = Modifier,
    button: @Composable (rotation: Float, expanded: Boolean, onClick: () -> Unit) -> Unit,
) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(isUltra, active) { if (!isUltra || !active) expanded = false }
    BackHandler(enabled = active && expanded) { expanded = false }
    val rotation by animateFloatAsState(if (expanded) 45f else 0f, tween(180), label = "module-install-menu")
    Column(modifier, horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(10.dp)) {
        AnimatedVisibility(
            visible = active && isUltra && expanded,
            enter = fadeIn(tween(120)) + expandVertically(tween(180), expandFrom = Alignment.Bottom),
            exit = fadeOut(tween(100)) + shrinkVertically(tween(160), shrinkTowards = Alignment.Bottom),
        ) {
            MarketCard(Modifier.widthIn(max = 300.dp)) {
                MarketButton(stringResource(R.string.maple_market_from_repository), {
                    expanded = false
                    onMarket()
                }, Modifier.fillMaxWidth())
                MarketButton(stringResource(R.string.maple_market_local_file), {
                    expanded = false
                    onLocalFile()
                }, Modifier.fillMaxWidth())
            }
        }
        button(rotation, expanded) {
            if (active) {
                if (isUltra) expanded = !expanded else onLocalFile()
            }
        }
    }
}
