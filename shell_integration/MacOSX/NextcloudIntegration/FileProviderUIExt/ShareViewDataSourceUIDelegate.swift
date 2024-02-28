//
//  ShareViewDataSourceUIDelegate.swift
//  FileProviderUIExt
//
//  Created by Claudio Cambra on 28/2/24.
//

import Foundation
import NextcloudKit

protocol ShareViewDataSourceUIDelegate {
    func fetchStarted()
    func fetchFinished()
    func hideOptions()
    func showOptions(share: NKShare)
}
